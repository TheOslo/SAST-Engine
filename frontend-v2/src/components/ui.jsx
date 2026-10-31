import React, { forwardRef } from "react";
import { Button as WatermelonButton } from "./ui/button.tsx";

/* Local, source-owned primitives follow Watermelon UI's copy-and-customize model. */
export const Button = forwardRef(function Button(
  { variant = "primary", className = "", children, ...props },
  ref,
) {
  return (
    <WatermelonButton ref={ref} className={`wm-button wm-button-${variant} ${className}`} {...props}>
      {children}
    </WatermelonButton>
  );
});

export function Card({ className = "", children, ...props }) {
  return <div className={`wm-card ${className}`} {...props}>{children}</div>;
}

export function Badge({ className = "", children }) {
  return <span className={`wm-badge ${className}`}>{children}</span>;
}
