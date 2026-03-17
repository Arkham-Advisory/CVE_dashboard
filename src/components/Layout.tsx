import { Link, useLocation } from 'react-router-dom'
import { Shield, AlertTriangle } from 'lucide-react'
import { cn } from '@/lib/utils'

const navItems = [
  { to: '/', label: 'Dashboard' },
  { to: '/findings', label: 'Findings' },
  { to: '/analytics', label: 'Analytics' },
  { to: '/assets', label: 'Asset Risk' },
  { to: '/report', label: 'Report' },
]

export function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()

  return (
    <div className="min-h-screen bg-background">
      {/* PoC Warning Banner */}
      <div className="bg-yellow-50 border-b border-yellow-200 px-4 py-2 flex items-center justify-center gap-2 text-yellow-800 text-xs">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
        <span>
          <strong>Proof of Concept only.</strong>{' '}All figures are computed from uploaded data and have not been validated.
          Numbers <strong>must be independently verified</strong> before any business decision is made.
        </span>
      </div>

      {/* Top Nav */}
      <header className="border-b bg-background/95 backdrop-blur sticky top-0 z-40">
        <div className="container mx-auto flex h-14 items-center gap-6 px-4">
          <Link to="/" className="flex items-center gap-2 font-semibold">
            <Shield className="h-5 w-5 text-primary" />
            <span>CVE Dashboard</span>
          </Link>
          <nav className="flex items-center gap-1">
            {navItems.map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                className={cn(
                  'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
                  location.pathname === to
                    ? 'bg-secondary text-foreground'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted',
                )}
              >
                {label}
              </Link>
            ))}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">{children}</main>
    </div>
  )
}
