"use client";

import { FileQuestion } from "lucide-react";
import EmptyState from "@/components/design/EmptyState";

export default function NotFound() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <EmptyState
        icon={FileQuestion}
        title="Page not found"
        description="The page you're looking for doesn't exist or may have been moved."
        actionLabel="Back to Dashboard"
        actionHref="/dashboard"
      />
    </div>
  );
}
