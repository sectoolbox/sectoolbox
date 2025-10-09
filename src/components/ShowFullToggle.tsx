import React from 'react'
import { Button } from './ui/button'
import { Eye, EyeOff } from 'lucide-react'

interface ShowFullToggleProps {
  isShowingFull: boolean
  onToggle: () => void
  totalCount: number
  displayedCount: number
  className?: string
}

export function ShowFullToggle({ 
  isShowingFull, 
  onToggle, 
  totalCount, 
  displayedCount, 
  className = ""
}: ShowFullToggleProps) {
  if (totalCount <= displayedCount) return null
  
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={onToggle}
      className={`text-xs ${className}`}
    >
      {isShowingFull ? (
        <>
          <EyeOff className="w-3 h-3 mr-1" />
          Show Less
        </>
      ) : (
        <>
          <Eye className="w-3 h-3 mr-1" />
          Show Full ({totalCount - displayedCount} more)
        </>
      )}
    </Button>
  )
}