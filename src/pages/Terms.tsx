import React from 'react';
import { Scale, AlertTriangle, Shield, FileText, Ban, CheckCircle } from 'lucide-react';
import { Card } from '../components/ui/card';

const Terms: React.FC = () => {
  return (
    <div className="flex flex-col min-h-screen">
      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-border bg-card">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-2xl font-bold">Terms of Service</h1>
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
              <Scale className="w-6 h-6 text-blue-500 flex-shrink-0 mt-1" />
              <div>
                <h2 className="text-xl font-semibold mb-2">Agreement to Terms</h2>
                <p className="text-muted-foreground">
                  By accessing and using Sectoolbox, you agree to be bound by these Terms of Service. 
                  If you do not agree with any part of these terms, you may not use the service.
                </p>
              </div>
            </div>
          </Card>

          {/* Service Description */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <FileText className="w-6 h-6 text-green-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">Service Description</h2>
                <p className="text-muted-foreground mb-3">
                  Sectoolbox is a free, open-source forensic analysis platform that provides:
                </p>
                <div className="space-y-2 text-sm">
                  <div className="flex items-start gap-2">
                    <span className="text-green-400 font-bold">•</span>
                    <span>Network packet capture (PCAP) analysis</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-green-400 font-bold">•</span>
                    <span>Audio forensics and steganography detection</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-green-400 font-bold">•</span>
                    <span>Image analysis and metadata extraction</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-green-400 font-bold">•</span>
                    <span>Windows Event Log analysis</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-green-400 font-bold">•</span>
                    <span>USB forensics and threat intelligence</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-green-400 font-bold">•</span>
                    <span>Cryptographic tools and utilities</span>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* User Responsibilities */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <CheckCircle className="w-6 h-6 text-yellow-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">User Responsibilities</h2>
                <div className="space-y-4">
                  <div className="border-l-2 border-yellow-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">Legal Use Only</h3>
                    <p className="text-sm text-muted-foreground">
                      You agree to use Sectoolbox only for lawful purposes. You must have legal 
                      authorization to analyze any files you upload. Analyzing data without proper 
                      authorization may violate laws in your jurisdiction.
                    </p>
                  </div>

                  <div className="border-l-2 border-yellow-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">Data Ownership</h3>
                    <p className="text-sm text-muted-foreground">
                      You retain all ownership rights to files you upload. You are responsible for 
                      ensuring you have the right to upload and analyze the data.
                    </p>
                  </div>

                  <div className="border-l-2 border-yellow-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">Sensitive Information</h3>
                    <p className="text-sm text-muted-foreground">
                      While we automatically delete files after 1-2 hours, you should avoid uploading 
                      highly sensitive or classified information. Use appropriate discretion when 
                      handling confidential data.
                    </p>
                  </div>

                  <div className="border-l-2 border-yellow-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">Fair Usage</h3>
                    <p className="text-sm text-muted-foreground">
                      The service includes rate limiting to ensure availability for all users. 
                      Attempts to circumvent these limits or abuse the service may result in access restrictions.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Prohibited Activities */}
          <Card className="p-6 bg-red-500/5 border-red-500/20">
            <div className="flex items-start gap-3 mb-4">
              <Ban className="w-6 h-6 text-red-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">Prohibited Activities</h2>
                <p className="text-muted-foreground mb-3">
                  The following activities are strictly prohibited:
                </p>
                <div className="space-y-2 text-sm">
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">✗</span>
                    <span>Uploading malware, viruses, or malicious code intended to harm the service</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">✗</span>
                    <span>Attempting to gain unauthorized access to the service or other users' data</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">✗</span>
                    <span>Using automated tools to overload or disrupt the service (DDoS attacks)</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">✗</span>
                    <span>Reverse engineering or attempting to extract the service's source code (unless through proper open-source channels)</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">✗</span>
                    <span>Analyzing data you don't have legal authorization to access</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">✗</span>
                    <span>Using the service to violate any applicable laws or regulations</span>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Service Limitations */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <AlertTriangle className="w-6 h-6 text-orange-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">Service Limitations & Disclaimers</h2>
                <div className="space-y-4">
                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">"As-Is" Service</h3>
                    <p className="text-sm text-muted-foreground">
                      Sectoolbox is provided "as is" and "as available" without warranties of any kind, 
                      either express or implied. We do not guarantee that the service will be error-free, 
                      uninterrupted, or meet your specific requirements.
                    </p>
                  </div>

                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">No Warranty</h3>
                    <p className="text-sm text-muted-foreground">
                      We make no warranties regarding the accuracy, reliability, or completeness of 
                      analysis results. Forensic analysis should be verified through multiple methods 
                      and professional judgment.
                    </p>
                  </div>

                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">Rate Limiting</h3>
                    <p className="text-sm text-muted-foreground">
                      The service enforces rate limits to ensure fair usage:
                    </p>
                    <ul className="text-sm text-muted-foreground mt-2 space-y-1">
                      <li>• General API: 100 requests per 15 minutes</li>
                      <li>• File uploads: 10 uploads per 15 minutes</li>
                      <li>• Analysis jobs: 5 concurrent jobs per IP</li>
                    </ul>
                  </div>

                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">File Size Limits</h3>
                    <p className="text-sm text-muted-foreground">
                      Maximum file sizes vary by type (typically 100MB-500MB). Large files may take 
                      longer to process and may time out.
                    </p>
                  </div>

                  <div className="border-l-2 border-orange-500/30 pl-4">
                    <h3 className="font-semibold text-sm mb-2">Service Availability</h3>
                    <p className="text-sm text-muted-foreground">
                      We reserve the right to modify, suspend, or discontinue the service at any time 
                      without notice. We may also impose new limits on features or access.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Limitation of Liability */}
          <Card className="p-6">
            <div className="flex items-start gap-3 mb-4">
              <Shield className="w-6 h-6 text-purple-500 flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h2 className="text-xl font-semibold mb-3">Limitation of Liability</h2>
                <p className="text-muted-foreground mb-3">
                  To the maximum extent permitted by law:
                </p>
                <div className="space-y-2 text-sm text-muted-foreground">
                  <p>
                    The Sectoolbox developers and contributors shall not be liable for any indirect, 
                    incidental, special, consequential, or punitive damages, or any loss of profits 
                    or revenues, whether incurred directly or indirectly, or any loss of data, use, 
                    goodwill, or other intangible losses resulting from:
                  </p>
                  <ul className="space-y-1 ml-4">
                    <li>• Your use or inability to use the service</li>
                    <li>• Any unauthorized access to or use of our servers</li>
                    <li>• Any bugs, viruses, or harmful code transmitted through the service</li>
                    <li>• Any errors or omissions in content or analysis results</li>
                    <li>• Any conduct or content of third parties on the service</li>
                  </ul>
                </div>
              </div>
            </div>
          </Card>

          {/* Intellectual Property */}
          <Card className="p-6">
            <h2 className="text-xl font-semibold mb-3">Intellectual Property & Open Source</h2>
            <div className="space-y-3 text-sm">
              <p className="text-muted-foreground">
                Sectoolbox is open-source software released under the MIT License. The source code 
                is available on GitHub at{' '}
                <a 
                  href="https://github.com/sectoolbox/sectoolbox" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:underline"
                >
                  github.com/sectoolbox/sectoolbox
                </a>
              </p>
              <p className="text-muted-foreground">
                You are free to use, modify, and distribute the software in accordance with the MIT License. 
                However, the Sectoolbox name and branding are not included in the license.
              </p>
            </div>
          </Card>

          {/* Norwegian Law Jurisdiction */}
          <Card className="p-6 bg-blue-500/5 border-blue-500/20">
            <h2 className="text-xl font-semibold mb-3">Governing Law & Jurisdiction</h2>
            <div className="space-y-2 text-sm text-muted-foreground">
              <p>
                These Terms of Service shall be governed by and construed in accordance with the 
                laws of Norway, without regard to its conflict of law provisions.
              </p>
              <p>
                Any disputes arising from these terms or your use of Sectoolbox shall be subject 
                to the exclusive jurisdiction of the Norwegian courts.
              </p>
            </div>
          </Card>

          {/* Indemnification */}
          <Card className="p-6">
            <h2 className="text-xl font-semibold mb-3">Indemnification</h2>
            <p className="text-sm text-muted-foreground">
              You agree to indemnify and hold harmless Sectoolbox, its developers, contributors, 
              and affiliates from any claims, damages, losses, liabilities, and expenses (including 
              legal fees) arising from your use of the service, your violation of these terms, or 
              your violation of any rights of another party.
            </p>
          </Card>

          {/* Changes to Terms */}
          <Card className="p-6">
            <h2 className="text-xl font-semibold mb-3">Changes to These Terms</h2>
            <p className="text-sm text-muted-foreground">
              We reserve the right to modify these Terms of Service at any time. Changes will be 
              effective immediately upon posting. The "Last updated" date at the top will reflect 
              any changes. Your continued use of Sectoolbox after changes constitutes acceptance 
              of the updated terms.
            </p>
          </Card>

          {/* Severability */}
          <Card className="p-6">
            <h2 className="text-xl font-semibold mb-3">Severability</h2>
            <p className="text-sm text-muted-foreground">
              If any provision of these Terms is found to be unenforceable or invalid, that provision 
              will be limited or eliminated to the minimum extent necessary so that these Terms will 
              otherwise remain in full force and effect.
            </p>
          </Card>

          {/* Contact */}
          <Card className="p-6 bg-muted/20">
            <h2 className="text-lg font-semibold mb-3">Contact & Questions</h2>
            <p className="text-sm text-muted-foreground mb-3">
              For questions about these Terms of Service:
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
        </div>
      </div>
    </div>
  );
};

export default Terms;
