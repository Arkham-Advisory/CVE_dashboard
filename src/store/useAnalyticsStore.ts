import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { AnalyticsConfig, AnalyticsPreset, DimensionKey, MetricKey, ChartType } from '@/types'

export const DEFAULT_CONFIG: AnalyticsConfig = {
  chartType: 'bar',
  groupBy: 'severity',
  stackBy: undefined,
  metric: 'findings',
  scatterX: 'severity',
  scatterY: 'environment',
  filters: {
    severities: [],
    accounts: [],
    regions: [],
    assetTypes: [],
    hasFix: null,
    cvssMin: 0,
    cvssMax: 10,
  },
  topN: 20,
}

interface AnalyticsState {
  config: AnalyticsConfig
  presets: AnalyticsPreset[]
  updateConfig: (partial: Partial<AnalyticsConfig>) => void
  updateFilters: (partial: Partial<AnalyticsConfig['filters']>) => void
  savePreset: (name: string, description?: string) => string
  loadPreset: (id: string) => void
  deletePreset: (id: string) => void
  resetConfig: () => void
  getShareUrl: () => string
  loadFromUrl: () => void
}

export const useAnalyticsStore = create<AnalyticsState>()(
  persist(
    (set, get) => ({
      config: DEFAULT_CONFIG,
      presets: [],

      updateConfig: (partial) =>
        set((s) => ({ config: { ...s.config, ...partial } })),

      updateFilters: (partial) =>
        set((s) => ({
          config: { ...s.config, filters: { ...s.config.filters, ...partial } },
        })),

      savePreset: (name, description) => {
        const preset: AnalyticsPreset = {
          id: `preset_${Date.now()}`,
          name,
          description,
          config: get().config,
          createdAt: Date.now(),
        }
        set((s) => ({ presets: [...s.presets, preset] }))
        return preset.id
      },

      loadPreset: (id) => {
        const preset = get().presets.find((p) => p.id === id)
        if (preset) set({ config: preset.config })
      },

      deletePreset: (id) =>
        set((s) => ({ presets: s.presets.filter((p) => p.id !== id) })),

      resetConfig: () => set({ config: DEFAULT_CONFIG }),

      getShareUrl: () => {
        const config = get().config
        const encoded = btoa(JSON.stringify(config))
        const base = window.location.href.split('?')[0].split('#')[0]
        return `${base}#/analytics?cfg=${encoded}`
      },

      loadFromUrl: () => {
        try {
          const hash = window.location.hash
          const qIdx = hash.indexOf('?')
          if (qIdx === -1) return
          const params = new URLSearchParams(hash.slice(qIdx + 1))
          const cfg = params.get('cfg')
          if (!cfg) return
          const config = JSON.parse(atob(cfg)) as AnalyticsConfig
          // Validate basics
          const validCharts: ChartType[] = ['bar', 'pie', 'scatter', 'treemap']
          const validDims: DimensionKey[] = ['severity', 'account', 'region', 'packageName', 'assetType', 'assetName', 'sourceFile', 'cveYear', 'cveId', 'sla', 'environment', 'findingType', 'treatment', 'exploitAvailable', 'riskPriority']
          const validMetrics: MetricKey[] = ['findings', 'uniqueCVEs', 'affectedAssets', 'fixableFindings']
          if (
            validCharts.includes(config.chartType) &&
            validDims.includes(config.groupBy) &&
            validMetrics.includes(config.metric)
          ) {
            set({ config })
          }
        } catch {
          // ignore malformed share URLs
        }
      },
    }),
    {
      name: 'cve-analytics-store',
      partialize: (s) => ({ presets: s.presets }),
    },
  ),
)
