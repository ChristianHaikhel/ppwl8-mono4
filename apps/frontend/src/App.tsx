import { Button } from "@/components/ui/button"

function App() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 min-h-screen">
      
      <Button>Default</Button>

      <Button variant="secondary">
        Secondary
      </Button>

      <Button variant="destructive">
        Delete
      </Button>

      <Button variant="outline">
        Outline
      </Button>

      <Button variant="ghost">
        Ghost
      </Button>

      <Button variant="link">
        Link
      </Button>

    </div>
  )
}

export default App