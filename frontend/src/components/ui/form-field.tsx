import * as React from "react"
import { cn } from "@/lib/utils"
import { Input, InputProps } from "./input"
import { Label } from "./label"
import { AlertCircle, CheckCircle2 } from "lucide-react"

interface FormFieldProps extends InputProps {
  /** Label text */
  label?: string
  /** Helper text shown below the input */
  hint?: string
  /** Error message - shows error state when present */
  error?: string
  /** Success message - shows success state when present */
  success?: string
  /** Required field indicator */
  required?: boolean
  /** Left icon component */
  leftIcon?: React.ReactNode
  /** Right icon component */
  rightIcon?: React.ReactNode
  /** Container class name */
  containerClassName?: string
}

const FormField = React.forwardRef<HTMLInputElement, FormFieldProps>(
  (
    {
      label,
      hint,
      error,
      success,
      required,
      leftIcon,
      rightIcon,
      className,
      containerClassName,
      id,
      ...props
    },
    ref
  ) => {
    const generatedId = React.useId()
    const fieldId = id || generatedId
    const hasError = !!error
    const hasSuccess = !!success && !hasError

    return (
      <div className={cn("space-y-2", containerClassName)}>
        {label && (
          <Label htmlFor={fieldId} className="flex items-center gap-1">
            {label}
            {required && <span className="text-red-500">*</span>}
          </Label>
        )}

        <div className="relative">
          {leftIcon && (
            <div className="input-icon-left h-4 w-4">{leftIcon}</div>
          )}

          <Input
            ref={ref}
            id={fieldId}
            className={cn(
              leftIcon && "pl-10",
              rightIcon && "pr-10",
              hasError && "input-error",
              hasSuccess && "input-success",
              className
            )}
            aria-invalid={hasError}
            aria-describedby={
              error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined
            }
            {...props}
          />

          {rightIcon && !hasError && !hasSuccess && (
            <div className="input-icon-right h-4 w-4">{rightIcon}</div>
          )}

          {hasError && (
            <div className="input-icon-right">
              <AlertCircle className="h-4 w-4 text-red-500" />
            </div>
          )}

          {hasSuccess && (
            <div className="input-icon-right">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
            </div>
          )}
        </div>

        {error && (
          <p id={`${fieldId}-error`} className="field-error" role="alert">
            <AlertCircle className="h-3.5 w-3.5" />
            {error}
          </p>
        )}

        {success && !error && (
          <p className="field-success">
            <CheckCircle2 className="h-3.5 w-3.5" />
            {success}
          </p>
        )}

        {hint && !error && !success && (
          <p id={`${fieldId}-hint`} className="field-hint">
            {hint}
          </p>
        )}
      </div>
    )
  }
)
FormField.displayName = "FormField"

export { FormField }
