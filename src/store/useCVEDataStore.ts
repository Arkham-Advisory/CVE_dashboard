import { create } from 'zustand'
import { fetchCVE } from '@/lib/cveApi'
import type { NVDCVEData } from '@/types'

interface CVEDataState {
  data: Record<string, NVDCVEData>
  loading: Set<string>
  errors: Set<string>
  fetchOne: (cveId: string) => Promise<void>
  getOrFetch: (cveId: string) => NVDCVEData | undefined
}

export const useCVEDataStore = create<CVEDataState>()((set, get) => ({
  data: {},
  loading: new Set(),
  errors: new Set(),

  fetchOne: async (cveId) => {
    const { data, loading } = get()
    if (data[cveId] || loading.has(cveId)) return

    set((s) => ({ loading: new Set([...s.loading, cveId]) }))
    const result = await fetchCVE(cveId)
    set((s) => {
      const newLoading = new Set(s.loading)
      newLoading.delete(cveId)
      if (result) {
        return { loading: newLoading, data: { ...s.data, [cveId]: result } }
      } else {
        const newErrors = new Set([...s.errors, cveId])
        return { loading: newLoading, errors: newErrors }
      }
    })
  },

  getOrFetch: (cveId) => {
    const { data, fetchOne } = get()
    if (!data[cveId]) {
      fetchOne(cveId)
    }
    return data[cveId]
  },
}))
