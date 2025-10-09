import React from 'react';
import { MessageSquare, Bug } from 'lucide-react';

const Footer: React.FC = () => {
  const projectName = import.meta.env.VITE_PROJECT_NAME || 'Sectoolbox';
  const zebGithub = import.meta.env.VITE_GITHUB_ZEB || 'https://github.com/zebbern';
  const kimmiGithub = import.meta.env.VITE_GITHUB_KIMMI || 'https://github.com/Opkimmi';

  const developers = [
    { name: 'Zeb', img: '/zeb.png', href: zebGithub, alt: 'Zeb — lead developer' },
    { name: 'Kimmi', img: '/kimmi.png', href: kimmiGithub, alt: 'Kimmi — frontend engineer' }
  ]

  const reportIssueLink = {
    name: 'GitHub Issues',
    icon: Bug,
    href: 'https://github.com/sectoolbox/sectoolbox/issues/new',
    alt: 'Report an issue on GitHub',
    color: 'slate'
  }

  const communityLinks = [
    {
      name: 'Discord',
      icon: MessageSquare,
      href: 'https://discord.gg/SvvKKMzE5Q',
      alt: 'Join our Discord community',
      color: 'indigo'
    }
  ]

  return (
    <footer className="bg-slate-900 border-t border-slate-700 py-8 mt-auto" role="contentinfo">
      <div className="container mx-auto px-4">
        <div className="flex flex-wrap justify-between items-start gap-8 mb-6">
          {/* Report Issues Section - Far Left */}
          <div className="flex flex-col items-center flex-1 min-w-0">
            <h3 className="text-lg font-semibold text-slate-200 mb-4">
              Report Issues
            </h3>
            <a
              href={reportIssueLink.href}
              target="_blank"
              rel="noopener noreferrer"
              className="flex flex-col items-center group focus:outline-none focus:ring-2 focus:ring-blue-400 rounded"
              aria-label={reportIssueLink.alt}
            >
              <div className={`
                w-16 h-16 rounded-full flex items-center justify-center border-2 transition-all duration-200
                border-slate-600 bg-slate-600/10 group-hover:border-slate-400 group-hover:bg-slate-600/20
              `}>
                <Bug className="w-8 h-8 transition-colors duration-200 text-slate-400 group-hover:text-slate-300" />
              </div>
              <span className="text-sm text-slate-300 mt-2 group-hover:text-blue-400 transition-colors duration-200">
                {reportIssueLink.name}
              </span>
            </a>
          </div>

          {/* Developers Section - Centered */}
          <div className="flex flex-col items-center">
            <h3 className="text-lg font-semibold text-slate-200 mb-4">
              Developers
            </h3>
            <ul className="flex flex-wrap justify-center items-center gap-6 list-none p-0 m-0" aria-label="Project developers">
              {developers.map((dev) => (
                <li key={dev.name}>
                  <a
                    href={dev.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex flex-col items-center group focus:outline-none focus:ring-2 focus:ring-blue-400 rounded"
                    aria-label={`View ${dev.name}'s GitHub profile`}
                  >
                    <div className="w-16 h-16 rounded-full overflow-hidden border-2 border-slate-600 group-hover:border-blue-400 transition-colors duration-200">
                      <img
                        src={dev.img}
                        alt={dev.alt}
                        className="w-full h-full object-cover"
                        onError={(e) => {
                          const t = e.target as HTMLImageElement
                          t.src = `${dev.href}.png`
                        }}
                      />
                    </div>
                    <span className="text-sm text-slate-300 mt-2 group-hover:text-blue-400 transition-colors duration-200">
                      {dev.name}
                    </span>
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Community Section - Far Right */}
          <div className="flex flex-col items-center flex-1 min-w-0">
            <h3 className="text-lg font-semibold text-slate-200 mb-4">
              Community
            </h3>
            <ul className="flex flex-wrap justify-center items-center gap-6 list-none p-0 m-0" aria-label="Community links">
              {communityLinks.map((link) => {
                const Icon = link.icon
                return (
                  <li key={link.name}>
                    <a
                      href={link.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex flex-col items-center group focus:outline-none focus:ring-2 focus:ring-blue-400 rounded"
                      aria-label={link.alt}
                    >
                      <div className={`
                        w-16 h-16 rounded-full flex items-center justify-center border-2 transition-all duration-200
                        ${link.color === 'indigo'
                          ? 'border-indigo-600 bg-indigo-600/10 group-hover:border-indigo-400 group-hover:bg-indigo-600/20'
                          : 'border-slate-600 bg-slate-600/10 group-hover:border-slate-400 group-hover:bg-slate-600/20'
                        }
                      `}>
                        <Icon className={`
                          w-8 h-8 transition-colors duration-200
                          ${link.color === 'indigo'
                            ? 'text-indigo-400 group-hover:text-indigo-300'
                            : 'text-slate-400 group-hover:text-slate-300'
                          }
                        `} />
                      </div>
                      <span className="text-sm text-slate-300 mt-2 group-hover:text-blue-400 transition-colors duration-200">
                        {link.name}
                      </span>
                    </a>
                  </li>
                )
              })}
            </ul>
          </div>
        </div>

        <div className="text-center text-xs text-slate-400">
          © 2025 {projectName}. All rights reserved.
        </div>
      </div>
    </footer>
  );
};

export default Footer;
