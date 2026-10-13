import { ChevronDown, ChevronUp, ChevronsUpDown } from "lucide-react";

/** Заголовок сортируемой колонки: кнопка (работает и с клавиатуры), направление — в aria-sort. */
export default function SortableHeader({ label, sortKey, activeKey, sortDir, onSort }) {
  const isActive = activeKey === sortKey;

  return (
    <th
      className="px-4 py-3"
      aria-sort={isActive ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="inline-flex select-none items-center gap-1 hover:text-zinc-200"
      >
        {label}
        {isActive ? (
          sortDir === "asc" ? (
            <ChevronUp size={13} />
          ) : (
            <ChevronDown size={13} />
          )
        ) : (
          <ChevronsUpDown size={13} className="text-zinc-600" />
        )}
      </button>
    </th>
  );
}
