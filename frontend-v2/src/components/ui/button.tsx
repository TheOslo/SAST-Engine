import * as React from "react"

function Button({
  className,
  variant = "default",
  size = "default",
  ...props
}: React.ComponentProps<"button"> & { variant?: string; size?: string }) {
  return (
    <button
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={className}
      {...props}
    />
  )
}

export { Button }
