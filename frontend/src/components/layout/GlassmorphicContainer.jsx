import { cn } from "../../lib/utils"

export default function GlassmorphicContainer({ children, className }) {
  return <div className={cn("glassmorphic p-6 rounded-lg shadow-lg", className)}>{children}</div>
}
