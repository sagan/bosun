import { SimpleGrid, type SimpleGridProps } from '@mantine/core'
import { Children } from 'react'

// A settings row must stay usable on a phone. Grid aligns inputs from the top,
// so longer help text does not move the neighboring label and control.
export function SettingsFields({ children, ...props }: Omit<SimpleGridProps, 'cols'>) {
  const count = Math.max(1, Children.toArray(children).length)
  return <SimpleGrid cols={{ base: 1, sm: Math.min(2, count), lg: Math.min(4, count) }} spacing="sm" {...props}>{children}</SimpleGrid>
}
