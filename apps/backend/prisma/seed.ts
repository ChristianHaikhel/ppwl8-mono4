import { prisma } from './db';

async function main() {
  await prisma.user.createMany({
    data: [
      {
        name: "Leo Tobing",
        email: "leo@example.com"
      },
      {
        name: "John Doe",
        email: "john@example.com"
      },
      {
        name: "Jane Smith",
        email: "jane@example.com"
      }
    ]
  })
}

main().finally(() => prisma.$disconnect())