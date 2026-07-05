"use client";

import { useEffect } from "react";
import { ServerCrash } from "lucide-react";
import EmptyState from "@/components/design/EmptyState";

export default function ErrorBoundary({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <EmptyState
        icon={ServerCrash}
        title="Something went wrong"
        description="An unexpected error occurred while loading this page. You can try again or head back to the dashboard."
        actionLabel="Try again"
        onAction={reset}
      />
    </div>
  );
}
