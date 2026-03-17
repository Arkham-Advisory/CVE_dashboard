import {
  Server,
  Zap,
  Database,
  Package,
  Layers,
  Globe,
  Shield,
  Box,
  HardDrive,
  Network,
  Container,
  Cloud,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'

export type AssetCategory =
  | 'ec2'
  | 'lambda'
  | 's3'
  | 'rds'
  | 'eks'
  | 'ecs'
  | 'ecr'
  | 'cloudfront'
  | 'elb'
  | 'iam'
  | 'container'
  | 'generic'

interface AssetInfo {
  category: AssetCategory
  label: string
  Icon: LucideIcon
  colorClass: string
}

const ASSET_MAP: Record<AssetCategory, AssetInfo> = {
  ec2: { category: 'ec2', label: 'EC2', Icon: Server, colorClass: 'text-orange-500' },
  lambda: { category: 'lambda', label: 'Lambda', Icon: Zap, colorClass: 'text-yellow-500' },
  s3: { category: 's3', label: 'S3', Icon: HardDrive, colorClass: 'text-green-500' },
  rds: { category: 'rds', label: 'RDS', Icon: Database, colorClass: 'text-blue-500' },
  eks: { category: 'eks', label: 'EKS', Icon: Layers, colorClass: 'text-blue-600' },
  ecs: { category: 'ecs', label: 'ECS', Icon: Container, colorClass: 'text-purple-500' },
  ecr: { category: 'ecr', label: 'ECR', Icon: Package, colorClass: 'text-purple-400' },
  cloudfront: { category: 'cloudfront', label: 'CloudFront', Icon: Globe, colorClass: 'text-pink-500' },
  elb: { category: 'elb', label: 'ELB', Icon: Network, colorClass: 'text-indigo-500' },
  iam: { category: 'iam', label: 'IAM', Icon: Shield, colorClass: 'text-red-500' },
  container: { category: 'container', label: 'Container', Icon: Box, colorClass: 'text-teal-500' },
  generic: { category: 'generic', label: 'Asset', Icon: Cloud, colorClass: 'text-muted-foreground' },
}

/** Detect asset category from ARN, explicit type, or name heuristics */
export function detectAssetCategory(opts: {
  arn?: string
  assetType?: string
  assetName?: string
}): AssetInfo {
  const { arn, assetType, assetName } = opts

  // ARN takes priority: arn:aws:<service>:<region>:<account>:<resource>
  if (arn) {
    const service = arn.split(':')[2]?.toLowerCase()
    if (service === 'ec2') return ASSET_MAP.ec2
    if (service === 'lambda') return ASSET_MAP.lambda
    if (service === 's3') return ASSET_MAP.s3
    if (service === 'rds') return ASSET_MAP.rds
    if (service === 'eks') return ASSET_MAP.eks
    if (service === 'ecs') return ASSET_MAP.ecs
    if (service === 'ecr') return ASSET_MAP.ecr
    if (service === 'cloudfront') return ASSET_MAP.cloudfront
    if (service === 'elasticloadbalancing') return ASSET_MAP.elb
    if (service === 'iam') return ASSET_MAP.iam
  }

  // Explicit asset type field
  if (assetType) {
    const t = assetType.toLowerCase()
    if (t.includes('ec2') || t.includes('instance')) return ASSET_MAP.ec2
    if (t.includes('lambda')) return ASSET_MAP.lambda
    if (t.includes('s3') || t.includes('bucket')) return ASSET_MAP.s3
    if (t.includes('rds') || t.includes('database')) return ASSET_MAP.rds
    if (t.includes('eks') || t.includes('kubernetes')) return ASSET_MAP.eks
    if (t.includes('ecs') || t.includes('fargate')) return ASSET_MAP.ecs
    if (t.includes('ecr') || t.includes('container_registry')) return ASSET_MAP.ecr
    if (t.includes('elb') || t.includes('loadbalancer')) return ASSET_MAP.elb
    if (t.includes('container') || t.includes('docker')) return ASSET_MAP.container
  }

  // Asset name heuristics
  if (assetName) {
    const n = assetName.toLowerCase()
    if (n.startsWith('i-') || n.includes('ec2')) return ASSET_MAP.ec2
    if (n.startsWith('arn:aws:lambda')) return ASSET_MAP.lambda
    if (n.startsWith('arn:aws:s3') || n.endsWith('.s3.amazonaws.com')) return ASSET_MAP.s3
    if (n.includes('rds') || n.includes('.rds.')) return ASSET_MAP.rds
    if (n.includes('eks') || n.includes('k8s')) return ASSET_MAP.eks
    if (n.includes('container') || n.includes('docker') || n.includes('sha256:')) return ASSET_MAP.container
  }

  return ASSET_MAP.generic
}

interface AssetTypeIconProps {
  arn?: string
  assetType?: string
  assetName?: string
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  className?: string
}

export function AssetTypeIcon({
  arn,
  assetType,
  assetName,
  size = 'sm',
  showLabel = false,
  className,
}: AssetTypeIconProps) {
  const info = detectAssetCategory({ arn, assetType, assetName })
  const { Icon, label, colorClass } = info

  const iconSize = size === 'sm' ? 'h-3.5 w-3.5' : size === 'md' ? 'h-4 w-4' : 'h-5 w-5'

  return (
    <span className={cn('inline-flex items-center gap-1', className)}>
      <Icon className={cn(iconSize, colorClass)} />
      {showLabel && (
        <span className="text-xs text-muted-foreground font-medium">{label}</span>
      )}
    </span>
  )
}

/** Parse ARN parts into a structured object */
export function parseARN(arn: string): {
  partition: string
  service: string
  region: string
  accountId: string
  resource: string
} | null {
  if (!arn.startsWith('arn:')) return null
  const parts = arn.split(':')
  if (parts.length < 6) return null
  return {
    partition: parts[1],
    service: parts[2],
    region: parts[3],
    accountId: parts[4],
    resource: parts.slice(5).join(':'),
  }
}
