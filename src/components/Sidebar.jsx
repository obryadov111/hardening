import { AnimatePresence, motion as Motion } from "framer-motion";
import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Server,
  ShieldCheck,
  FileText,
  BookOpen,
  FolderKanban,
  Boxes,
  History,
  GitCompareArrows,
  Bug,
  X,
} from "lucide-react";

const menuItems = [
  { to: "/dashboard", label: "Обзор", icon: LayoutDashboard },
  { to: "/assets", label: "Активы", icon: Server },
  { to: "/software", label: "Инвентаризация ПО", icon: Boxes },
  { to: "/hardening", label: "Харденинг", icon: ShieldCheck },
  { to: "/vulnerabilities", label: "Уязвимости ПО", icon: Bug },
  { to: "/policies", label: "Политики", icon: BookOpen },
  { to: "/report", label: "Отчёты", icon: FileText },
  { to: "/scans", label: "Сканирования", icon: History },
  { to: "/scan-compare", label: "Сравнение сканов", icon: GitCompareArrows },
  { to: "/project", label: "Инфраструктура", icon: FolderKanban },
];

export default function Sidebar({ open = false, onClose }) {
  const location = useLocation();

  const getItemClassName = (path) => {
    const isActive =
      location.pathname === path ||
      (path !== "/dashboard" && location.pathname.startsWith(path));

    return [
      "flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition-colors",
      isActive
        ? "border border-blue-500/20 bg-blue-500/15 text-blue-300"
        : "border border-transparent text-zinc-400 hover:bg-zinc-800 hover:text-white",
    ].join(" ");
  };

  const nav = (
    <nav className="flex flex-col gap-2">
      {menuItems.map((item) => (
        <Link key={item.to} to={item.to} className={getItemClassName(item.to)} onClick={onClose}>
          <item.icon size={18} />
          <span>{item.label}</span>
        </Link>
      ))}
    </nav>
  );

  return (
    <>
      {/* Десктоп: статичный сайдбар */}
      <aside className="hidden w-72 shrink-0 border-r border-zinc-800 bg-zinc-950/80 p-4 md:block">
        <div className="mb-6 rounded-2xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="text-lg font-semibold tracking-wide text-white">Харденинг</div>
          <div className="mt-1 text-xs text-zinc-400">Hardening / Compliance UI</div>
        </div>
        {nav}
      </aside>

      {/* Мобильный/узкий экран: выезжающая панель поверх контента */}
      <AnimatePresence>
        {open ? (
          <Motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40 bg-black/60 md:hidden"
            onClick={onClose}
          />
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {open ? (
          <Motion.aside
            initial={{ x: "-100%" }}
            animate={{ x: 0 }}
            exit={{ x: "-100%" }}
            transition={{ type: "tween", duration: 0.2 }}
            className="fixed inset-y-0 left-0 z-50 w-72 overflow-y-auto border-r border-zinc-800 bg-zinc-950 p-4 md:hidden"
          >
            <div className="mb-6 flex items-start justify-between gap-3 rounded-2xl border border-zinc-800 bg-zinc-900 p-4">
              <div>
                <div className="text-lg font-semibold tracking-wide text-white">Харденинг</div>
                <div className="mt-1 text-xs text-zinc-400">Hardening / Compliance UI</div>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg p-1 text-zinc-400 hover:bg-zinc-800 hover:text-white"
                aria-label="Закрыть меню"
              >
                <X size={18} />
              </button>
            </div>
            {nav}
          </Motion.aside>
        ) : null}
      </AnimatePresence>
    </>
  );
}
