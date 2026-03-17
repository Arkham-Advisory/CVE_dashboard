import { Link, useLocation } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { cn } from '@/lib/utils'

const navItems = [
  { to: '/', label: 'Dashboard' },
  { to: '/findings', label: 'Findings' },
  { to: '/report', label: 'Report' },
]

export function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()

  return (
    <div className="min-h-screen bg-background">
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
