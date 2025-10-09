import React, { useEffect, useState } from 'react'
import { Calendar } from 'lucide-react'

interface ChangelogEntry {
  version: string
  date: string
  changes: string[]
}

const LatestUpdates: React.FC = () => {
  const [changelog, setChangelog] = useState<ChangelogEntry[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let isMounted = true
    const fetchChangelog = async () => {
      try {
        const res = await fetch('https://raw.githubusercontent.com/sectoolbox/sectoolbox/refs/heads/main/changelogs.json')
        if (!isMounted) return
        if (res.ok) {
          const data = await res.json()
          setChangelog(Array.isArray(data) ? data.slice(0, 3) : [])
        }
      } catch (err) {
        console.error('Failed to load changelog', err)
      } finally {
        if (isMounted) setLoading(false)
      }
    }

    fetchChangelog()
    return () => { isMounted = false }
  }, [])

  return (
    <div aria-label="latest-updates">
      <h2 className="text-xl font-semibold flex items-center gap-2 mb-4">
        <Calendar className="h-5 w-5 text-accent" />
        Latest Updates
      </h2>

      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        {loading ? (
          <div className="text-sm text-muted-foreground">Loading updates...</div>
        ) : changelog.length > 0 ? (
          <div className="space-y-3 max-h-48 overflow-y-auto">
            {changelog.map((entry, idx) => (
              <div key={idx} className="border-b border-border/50 last:border-b-0 pb-3 last:pb-0">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-accent">{entry.version}</span>
                  <span className="text-xs text-muted-foreground">{entry.date}</span>
                </div>
                <ul className="space-y-1">
                  {entry.changes.slice(0, 2).map((change, cidx) => (
                    <li key={cidx} className="text-xs text-muted-foreground flex items-start">
                      <span className="text-accent mr-2">•</span>
                      <span className="flex-1">{change}</span>
                    </li>
                  ))}
                  {entry.changes.length > 2 && (
                    <li className="text-xs text-muted-foreground/70 italic">+{entry.changes.length - 2} more changes</li>
                  )}
                </ul>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-muted-foreground">No updates available</div>
        )}
      </div>
    </div>
  )
}

export default LatestUpdates
