import ErrorState from "./ui/ErrorState";
import EmptyState from "./ui/EmptyState";
import { Skeleton } from "./ui/Skeleton";

/**
 * Общая проверка состояния организации, которая раньше была продублирована
 * на каждой странице (Dashboard/Hardening/Report/Policies/Scans).
 */
export default function OrgGate({
  title,
  orgLoading,
  orgError,
  hasOrganizations,
  children,
}) {
  if (orgLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-72" />
      </div>
    );
  }

  if (orgError) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">{title}</h1>
        <ErrorState title="Не удалось загрузить организации" description={orgError} />
      </div>
    );
  }

  if (!hasOrganizations) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">{title}</h1>
        <EmptyState
          title="Нет организаций"
          description="Таблица client_organizations пустая. Сначала добавь хотя бы одну организацию."
        />
      </div>
    );
  }

  return children;
}
