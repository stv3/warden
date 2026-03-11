import React, { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  AlertTriangle,
  Play,
  FileDown,
  LogOut,
  Menu,
  X,
  ChevronRight,
  Plug,
  User,
  SlidersHorizontal,
} from 'lucide-react';
import { WardenMark } from './components/WardenMark';
import { useAuth } from './auth';

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

const navItems: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { to: '/findings', label: 'Findings', icon: <ShieldAlert size={18} /> },
  { to: '/kev', label: 'KEV Alerts', icon: <AlertTriangle size={18} /> },
  { to: '/pipeline', label: 'Pipeline', icon: <Play size={18} /> },
  { to: '/reports', label: 'Reports', icon: <FileDown size={18} /> },
  { to: '/connectors', label: 'Connectors', icon: <Plug size={18} /> },
  { to: '/settings',   label: 'Settings',   icon: <SlidersHorizontal size={18} /> },
  { to: '/account',    label: 'My Account', icon: <User size={18} /> },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const sidebarContent = (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-5 border-b border-slate-700/50">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-indigo-500">
          <WardenMark size={17} className="text-white" />
        </div>
        <div>
          <span className="text-white font-bold text-lg tracking-tight">Warden</span>
          <div className="text-slate-400 text-xs leading-tight">Vulnerability Orchestrator</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            onClick={() => setSidebarOpen(false)}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
              }`
            }
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* User info + logout */}
      <div className="px-3 py-4 border-t border-slate-700/50">
        {user && (
          <div className="px-3 py-2 mb-2">
            <div className="text-slate-200 text-sm font-medium truncate">{user.username}</div>
            <div className="text-slate-500 text-xs capitalize">{user.role}</div>
          </div>
        )}
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:text-red-400 hover:bg-red-900/20 transition-all"
        >
          <LogOut size={18} />
          Sign out
        </button>
      </div>
    </div>
  );

  return (
    <div className="flex h-screen bg-slate-50 overflow-hidden">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-20 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar — desktop */}
      <aside className="hidden lg:flex flex-col w-60 flex-shrink-0 bg-[#0f172a] z-10">
        {sidebarContent}
      </aside>

      {/* Sidebar — mobile drawer */}
      <aside
        className={`fixed inset-y-0 left-0 w-60 bg-[#0f172a] z-30 flex flex-col transform transition-transform duration-200 lg:hidden ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <button
          onClick={() => setSidebarOpen(false)}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X size={20} />
        </button>
        {sidebarContent}
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Mobile topbar */}
        <header className="lg:hidden flex items-center gap-3 px-4 py-3 bg-white border-b border-slate-200 flex-shrink-0">
          <button
            onClick={() => setSidebarOpen(true)}
            className="text-slate-600 hover:text-slate-900"
          >
            <Menu size={22} />
          </button>
          <div className="flex items-center gap-2">
            <WardenMark size={18} className="text-indigo-500" />
            <span className="font-bold text-slate-900">Warden</span>
          </div>
        </header>

        {/* Breadcrumb / page header area */}
        <div className="hidden lg:flex items-center gap-1 px-8 py-3 bg-white border-b border-slate-200 flex-shrink-0 text-xs text-slate-400">
          <WardenMark size={12} className="text-indigo-400" />
          <ChevronRight size={12} />
          <span>Warden</span>
        </div>

        {/* Scrollable page area */}
        <main className="flex-1 overflow-y-auto">
          <div className="p-6 lg:p-8 max-w-screen-2xl mx-auto">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
