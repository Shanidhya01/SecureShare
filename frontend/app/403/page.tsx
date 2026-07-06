"use client";

import { ShieldAlert } from "lucide-react";
import EmptyState from "@/components/design/EmptyState";

export default function ForbiddenPage() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <EmptyState
        icon={ShieldAlert}
        title="Access restricted"
        description="This area is limited to administrators. If you believe you should have access, contact your organization owner."
        actionLabel="Back to Dashboard"
        actionHref="/dashboard"
      />
    </div>
  );
}
