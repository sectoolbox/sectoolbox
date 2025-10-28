import React from 'react';
import { Shield, Clock, Database, Lock, Eye, FileText } from 'lucide-react';
import { Card } from '../components/ui/card';

const Privacy: React.FC = () => {
  return (
    <div className="flex flex-col min-h-screen">
      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-border bg-card">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-2xl font-bold">Privacy Policy</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Last updated: October 28, 2025
          </p>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl mx-auto space-y-6">
          {/* Introduction */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <Shield className="w-6 h-6 text-blue-500 flex-shrink-0 mt-1" />
              <div>
                <h2 className="text-xl font-semibold mb-2">Your Privacy Matters</h2>
                <p className="text-muted-foreground">
                  Sectoolbox is committed to protecting your privacy. This policy explains what data we collect, 
                  how we use it, and your rights under GDPR (General Data Protection Regulation) and Norwegian 
                  Personal Data Act (Personopplysningsloven).
                </p>
              </div>
            </div>
          </Card>

          {/* Data We Collect */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <Database className="w-6 h-6 text-green-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">Data We Collect</h2>
                
                <div className="space-y-4">
                  <div className="border-l-2 border-green-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">1. Uploaded Files (Temporary)</h3>
                    <p className="text-sm text-muted-foreground mb-2">
                      Files you upload for analysis (PCAP, audio, images, event logs, etc.)
                    </p>
                    <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                      <li>Purpose: To perform the requested forensic analysis</li>
                      <li>Storage: Temporarily stored in server memory/disk</li>
                      <li>Retention: Automatically deleted after 1-2 hours</li>
                      <li>Legal basis: Necessary for service provision (GDPR Art. 6(1)(b))</li>
                    </ul>
                  </div>

                  <div className="border-l-2 border-yellow-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">2. IP Addresses (Temporary)</h3>
                    <p className="text-sm text-muted-foreground mb-2">
                      Your IP address for rate limiting and abuse prevention
                    </p>
                    <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                      <li>Purpose: Prevent abuse and ensure service availability</li>
                      <li>Storage: Temporarily stored in memory (Redis)</li>
                      <li>Retention: 15 minutes (rate limit window)</li>
                      <li>Legal basis: Legitimate interest (GDPR Art. 6(1)(f))</li>
                    </ul>
                  </div>

                  <div className="border-l-2 border-blue-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">3. Job Metadata</h3>
                    <p className="text-sm text-muted-foreground mb-2">
                      Technical information about analysis jobs (file names, timestamps, job status)
                    </p>
                    <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                      <li>Purpose: To track and manage analysis jobs</li>
                      <li>Storage: Temporarily stored in Redis cache</li>
                      <li>Retention: Maximum 2 hours, then automatically deleted</li>
                      <li>Legal basis: Necessary for service provision (GDPR Art. 6(1)(b))</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* What We DON'T Collect */}
          <Card className="p-6 bg-green-500/5 border-green-500/20">
            <div className="flex items-start gap-3">
              <Eye className="w-6 h-6 text-green-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">What We DON'T Collect</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="text-sm">
                    <span className="text-green-400 font-medium">✓</span> No user accounts or registration
                  </div>
                  <div className="text-sm">
                    <span className="text-green-400 font-medium">✓</span> No email addresses
                  </div>
                  <div className="text-sm">
                    <span className="text-green-400 font-medium">✓</span> No names or personal information
                  </div>
                  <div className="text-sm">
                    <span className="text-green-400 font-medium">✓</span> No tracking cookies
                  </div>
                  <div className="text-sm">
                    <span className="text-green-400 font-medium">✓</span> No analytics or tracking scripts
                  </div>
                  <div className="text-sm">
                    <span className="text-green-400 font-medium">✓</span> No third-party data sharing
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Data Retention */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <Clock className="w-6 h-6 text-purple-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">Data Retention</h2>
                <p className="text-muted-foreground mb-4">
                  We believe in minimal data retention. All data is automatically deleted according to these schedules:
                </p>
                <div className="space-y-3">
                  <div className="flex items-center gap-3 p-3 bg-muted/20 rounded">
                    <div className="w-16 text-center">
                      <div className="text-2xl font-bold text-purple-400">1h</div>
                      <div className="text-xs text-muted-foreground">hour</div>
                    </div>
                    <div className="text-sm">Uploaded files and analysis results</div>
                  </div>
                  <div className="flex items-center gap-3 p-3 bg-muted/20 rounded">
                    <div className="w-16 text-center">
                      <div className="text-2xl font-bold text-purple-400">2h</div>
                      <div className="text-xs text-muted-foreground">hours</div>
                    </div>
                    <div className="text-sm">Job metadata and processing information</div>
                  </div>
                  <div className="flex items-center gap-3 p-3 bg-muted/20 rounded">
                    <div className="w-16 text-center">
                      <div className="text-2xl font-bold text-purple-400">15m</div>
                      <div className="text-xs text-muted-foreground">minutes</div>
                    </div>
                    <div className="text-sm">IP addresses for rate limiting</div>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Your Rights (GDPR & Norwegian Law) */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <FileText className="w-6 h-6 text-orange-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">Your Rights (GDPR & Norwegian Law)</h2>
                <p className="text-muted-foreground mb-4">
                  Under GDPR and Norwegian Personal Data Act, you have the following rights:
                </p>
                <div className="space-y-3 text-sm">
                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold mb-1">Right to Access (Innsyn)</h3>
                    <p className="text-muted-foreground">
                      Since we don't store persistent personal data, there is no data to access after the automatic deletion period.
                    </p>
                  </div>
                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold mb-1">Right to Erasure (Sletting)</h3>
                    <p className="text-muted-foreground">
                      All data is automatically erased within 1-2 hours. No manual deletion request needed.
                    </p>
                  </div>
                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold mb-1">Right to Data Portability (Dataportabilitet)</h3>
                    <p className="text-muted-foreground">
                      You receive all analysis results directly in your browser. We don't retain copies.
                    </p>
                  </div>
                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold mb-1">Right to Object (Protestere)</h3>
                    <p className="text-muted-foreground">
                      You can stop using the service at any time. Simply close your browser.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Security */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <Lock className="w-6 h-6 text-red-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">Security Measures</h2>
                <p className="text-muted-foreground mb-4">
                  We implement industry-standard security measures:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span>HTTPS encryption for all connections</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span>Rate limiting to prevent abuse</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span>CORS restrictions on API access</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span>File size and type validation</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span>Automated data cleanup</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span>Helmet.js security headers</span>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Third-Party Services */}
          <Card className="p-6">
            <h2 className="text-xl font-semibold mb-3">Third-Party Services</h2>
            <div className="space-y-3 text-sm">
              <div>
                <h3 className="font-semibold mb-1">Hosting Provider: Railway</h3>
                <p className="text-muted-foreground">
                  Our backend is hosted on Railway (GDPR-compliant US company). 
                  Data is processed on Railway's infrastructure and automatically deleted per our retention policy.
                </p>
              </div>
              <div>
                <h3 className="font-semibold mb-1">Frontend Hosting: Vercel</h3>
                <p className="text-muted-foreground">
                  Our frontend is hosted on Vercel (GDPR-compliant US company). 
                  No personal data is stored on Vercel servers.
                </p>
              </div>
            </div>
          </Card>

          {/* Norwegian Law Compliance */}
          <Card className="p-6 bg-blue-500/5 border-blue-500/20">
            <h2 className="text-xl font-semibold mb-3">Norwegian Law Compliance</h2>
            <p className="text-muted-foreground mb-3">
              This service complies with Norwegian data protection laws:
            </p>
            <div className="space-y-2 text-sm">
              <div className="flex items-start gap-2">
                <span className="text-blue-400 font-bold">•</span>
                <span>Personopplysningsloven (Norwegian Personal Data Act)</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-blue-400 font-bold">•</span>
                <span>GDPR as implemented in Norwegian law</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-blue-400 font-bold">•</span>
                <span>Datatilsynet (Norwegian Data Protection Authority) guidelines</span>
              </div>
            </div>
          </Card>

          {/* Contact */}
          <Card className="p-6">
            <h2 className="text-xl font-semibold mb-3">Contact & Questions</h2>
            <p className="text-muted-foreground mb-3">
              For privacy-related questions or concerns:
            </p>
            <div className="space-y-2 text-sm">
              <div>
                <span className="font-semibold">GitHub Issues:</span>{' '}
                <a 
                  href="https://github.com/sectoolbox/sectoolbox/issues" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:underline"
                >
                  github.com/sectoolbox/sectoolbox/issues
                </a>
              </div>
              <div>
                <span className="font-semibold">Discord:</span>{' '}
                <a 
                  href="https://discord.gg/SvvKKMzE5Q" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:underline"
                >
                  Join our community
                </a>
              </div>
            </div>
          </Card>

          {/* Changes to Policy */}
          <Card className="p-6 bg-muted/20">
            <h2 className="text-lg font-semibold mb-2">Changes to This Policy</h2>
            <p className="text-sm text-muted-foreground">
              We may update this privacy policy from time to time. The "Last updated" date at the top 
              will reflect any changes. Continued use of Sectoolbox after changes constitutes acceptance 
              of the updated policy.
            </p>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Privacy;
