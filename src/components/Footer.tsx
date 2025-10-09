import React from 'react';

const Footer: React.FC = () => {
  const projectName = import.meta.env.VITE_PROJECT_NAME || 'Sectoolbox';
  const zebGithub = import.meta.env.VITE_GITHUB_ZEB || 'https://github.com/zebbern';
  const kimmiGithub = import.meta.env.VITE_GITHUB_KIMMI || 'https://github.com/Opkimmi';

  const developers = [
    { name: 'Zeb', img: '/zeb.png', href: zebGithub, alt: 'Zeb — lead developer' },
    { name: 'Kimmi', img: '/kimmi.png', href: kimmiGithub, alt: 'Kimmi — frontend engineer' }
  ]

  return (
    <footer className="bg-slate-900 border-t border-slate-700 py-8 mt-auto" role="contentinfo">
      <div className="container mx-auto px-4">
        <div className="text-center">
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
          <div className="mt-6 text-xs text-slate-400">
            © 2025 {projectName}. All rights reserved.
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
