import { Routes, Route } from 'react-router-dom'
import { Layout } from '@/components/Layout'
import { CVEDetailDrawer } from '@/components/CVEDetailDrawer'
import { DashboardPage } from '@/pages/DashboardPage'
import { FindingsPage } from '@/pages/FindingsPage'
import { ReportPage } from '@/pages/ReportPage'
import { useAppStore } from '@/store/useAppStore'

export default function App() {
  const { selectedCVE } = useAppStore()

  return (
    <>
      <Layout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/report" element={<ReportPage />} />
        </Routes>
      </Layout>
      {selectedCVE && <CVEDetailDrawer />}
    </>
  )
}
