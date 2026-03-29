import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { swagger } from "@elysiajs/swagger";
import { cookie } from "@elysiajs/cookie";
import { prisma } from "../prisma/db";
import { createOAuthClient, getAuthUrl } from "./auth";
import { getCourses, getCourseWorks, getSubmissions } from "./classroom";
import type { ApiResponse, HealthCheck, User } from "shared";

// penyimpanan token sementara di memory (belum pakai database/session store)
const tokenStore = new Map<string, { access_token: string; refresh_token?: string }>();

const app = new Elysia()
  // middleware CORS biar frontend bisa akses backend
  .use(
    cors({
      origin: process.env.FRONTEND_URL || "http://localhost:5173",
      credentials: true, // penting untuk kirim cookie
      allowedHeaders: ["Content-Type", "Authorization"],
    })
  )
  // auto generate dokumentasi API
  .use(swagger())
  // enable parsing cookie
  .use(cookie())

  // middleware global untuk proteksi endpoint tertentu
  .onRequest(({ request, set }) => {
    const url = new URL(request.url);

    // khusus endpoint /users harus ada validasi tambahan
    if (url.pathname.startsWith("/users")) {
      const origin = request.headers.get("origin");
      const frontendUrl = process.env.FRONTEND_URL ?? "http://localhost:5173";
      const key = url.searchParams.get("key");

      // kalau request dari frontend sendiri, langsung lolos
      if (origin === frontendUrl) return;

      // kalau bukan, wajib pakai API key
      if (key !== process.env.API_KEY) {
        set.status = 401;
        return { message: "Unauthorized: Access denied without valid API Key" };
      }
    }
  })

  // endpoint health check sederhana
  .get("/", (): ApiResponse<HealthCheck> => ({
    data: { status: "ok" },
    message: "server running",
  }))

  // ambil semua user dari database
  .get("/users", async () => {
    const users = await prisma.user.findMany();
    return { data: users, message: "User list retrieved" };
  })

  // ================= AUTH =================

  // redirect ke halaman login Google OAuth
  .get("/auth/login", ({ redirect }) => {
    const oauth2Client = createOAuthClient();
    const url = getAuthUrl(oauth2Client);
    return redirect(url);
  })

  // callback dari Google setelah login berhasil
  .get("/auth/callback", async ({ query, set, cookie, redirect }) => {
    const { code } = query as { code: string };

    // validasi kalau code tidak ada
    if (!code) {
      set.status = 400;
      return { error: "Missing authorization code" };
    }

    const oauth2Client = createOAuthClient();

    // tukar authorization code dengan token
    const { tokens } = await oauth2Client.getToken(code);

    // bikin session ID unik
    const sessionId = crypto.randomUUID();

    // simpan token ke memory
    tokenStore.set(sessionId, {
      access_token: tokens.access_token!,
      refresh_token: tokens.refresh_token ?? undefined,
    });

    // set cookie session ke browser
    const session = (cookie as any).session;
    session.set({
      value: sessionId,
      maxAge: 60 * 60 * 24, // 1 hari
      path: "/",
      httpOnly: true, // tidak bisa diakses JS (lebih aman)
      secure: true,
      sameSite: "none",
    });

    // redirect ke halaman frontend setelah login
    return redirect(`${process.env.FRONTEND_URL}/classroom`);
  })

  // cek apakah user masih login atau tidak
  .get("/auth/me", ({ cookie }) => {
    // cast ke any karena typing cookie kadang ribet
    const sessionId = (cookie as any).session.value as string;
    
    if (!sessionId || !tokenStore.has(sessionId)) {
      return { loggedIn: false };
    }

    return { loggedIn: true, sessionId };
  })

  // logout: hapus session dari memory dan cookie
  .post("/auth/logout", ({ cookie }) => {
    const session = (cookie as any).session;
    const sessionId = session.value as string;

    if (sessionId) {
      tokenStore.delete(sessionId);
      session.remove();
    }

    return { success: true };
  })

  // ================= CLASSROOM =================

  // ambil daftar course dari Google Classroom
  .get("/classroom/courses", async ({ cookie, set }) => {
    const sessionId = (cookie as any).session.value as string;
    const tokens = sessionId ? tokenStore.get(sessionId) : null;

    // kalau belum login, tolak akses
    if (!tokens) {
      set.status = 401;
      return { error: "Unauthorized. Silakan login terlebih dahulu." };
    }

    const courses = await getCourses(tokens.access_token);
    return { data: courses, message: "Courses retrieved" };
  })

  // ambil submission tugas berdasarkan course
  .get("/classroom/courses/:courseId/submissions", async ({ params, cookie, set }) => {
    const sessionId = (cookie as any).session.value as string;
    const tokens = sessionId ? tokenStore.get(sessionId) : null;

    if (!tokens) {
      set.status = 401;
      return { error: "Unauthorized. Silakan login terlebih dahulu." };
    }

    const { courseId } = params;

    // ambil data tugas & submission secara paralel biar lebih cepat
    const [courseWorks, submissions] = await Promise.all([
      getCourseWorks(tokens.access_token, courseId),
      getSubmissions(tokens.access_token, courseId),
    ]);

    // mapping submission berdasarkan courseWorkId biar gampang dicari
    const submissionMap = new Map(
      submissions.map((s: any) => [s.courseWorkId, s])
    );

    // gabungkan data tugas + submission
    const result = courseWorks.map((cw: any) => ({
      courseWork: cw,
      submission: submissionMap.get(cw.id) ?? null,
    }));

    return { data: result, message: "Course submissions retrieved" };
  });

// hanya jalan di local/dev
if (process.env.NODE_ENV !== "production") {
  app.listen(3000);
}

// export app buat dipakai di tempat lain (misal testing)
export default app;
export type App = typeof app;