export interface MetricValidity { cpu: boolean; memory: boolean; swap: boolean; disk: boolean; network: boolean; load: boolean; connections: boolean; processes: boolean; uptime: boolean }
export interface ResourceOptions { gpu?: boolean; include_interfaces?: string[]; exclude_interfaces?: string[] }
export interface GPUDevice { id: string; name: string; vendor: string; utilization: number | null; memory_total: number | null; memory_used: number | null; temperature: number | null; power: number | null }
export interface GPUStatus { epoch?: string; sequence?: number; at: number; state: string; devices: GPUDevice[] | null; truncated?: boolean }
export interface Resources {
  gpu?: GPUStatus
  at: number
  cpus: { name: string; percent: number | null }[] | null
  networks: { name: string; included: boolean; up: number; down: number; up_rate: number | null; down_rate: number | null }[] | null
  filesystems: { mount: string; device: string; type: string; total: number | null; used: number | null; inodes_total: number | null; inodes_used: number | null }[] | null
  disks: { name: string; read_rate: number | null; write_rate: number | null; read_iops: number | null; write_iops: number | null }[] | null
  processes: { name: string; pid: number; cpu: number | null; rss: number | null }[] | null
}
export interface ResourceHost {
  cpu_percent?: number; mem_total?: number; mem_used?: number; swap_total?: number; swap_used?: number; disk_total?: number; disk_used?: number
  load1?: number; load5?: number; load15?: number; net_up?: number; net_down?: number; tcp?: number; udp?: number; processes?: number
  valid?: MetricValidity; resources?: Resources
}
