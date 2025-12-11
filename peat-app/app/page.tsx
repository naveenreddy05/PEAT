'use client';

import { Shield, Cpu, Database, Code2, ArrowRight, Github, BookOpen, Terminal } from 'lucide-react';
import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Header */}
      <header className="fixed top-0 w-full bg-white/80 backdrop-blur-md border-b border-gray-200 z-50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="bg-gradient-to-br from-blue-600 to-indigo-600 p-2 rounded-xl">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">PEAT</h1>
                <p className="text-xs text-gray-500">Post-Exploitation Analysis Tool</p>
              </div>
            </div>

            <nav className="hidden md:flex items-center gap-6">
              <a href="#about" className="text-gray-600 hover:text-gray-900 font-medium transition">About</a>
              <a href="#features" className="text-gray-600 hover:text-gray-900 font-medium transition">Features</a>
              <a href="#tech" className="text-gray-600 hover:text-gray-900 font-medium transition">Tech Stack</a>
              <Link
                href="/analyze"
                className="px-5 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-medium rounded-lg hover:shadow-lg transition-all"
              >
                Start Analysis
              </Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section id="about" className="pt-32 pb-20 px-6">
        <div className="max-w-6xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-white/80 backdrop-blur-sm border border-blue-200 rounded-full mb-8">
            <Terminal className="w-4 h-4 text-blue-600" />
            <span className="text-sm font-medium text-gray-700">Final Year Project 2025</span>
          </div>

          <h1 className="text-5xl lg:text-7xl font-bold text-gray-900 mb-6 leading-tight">
            Post-Exploitation Analysis Tool
          </h1>

          <p className="text-xl lg:text-2xl text-gray-600 mb-12 max-w-4xl mx-auto leading-relaxed">
            An automated forensic analysis platform for IoT devices using memory dump analysis and the Volatility Framework
          </p>

          <div className="flex flex-wrap gap-4 justify-center mb-16">
            <Link
              href="/analyze"
              className="px-8 py-4 bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl hover:scale-105 transition-all flex items-center gap-2"
            >
              Launch Analysis Tool
              <ArrowRight className="w-5 h-5" />
            </Link>
            <a
              href="#tech"
              className="px-8 py-4 bg-white text-gray-700 font-semibold rounded-xl border-2 border-gray-200 hover:border-gray-300 hover:shadow-md transition-all flex items-center gap-2"
            >
              <BookOpen className="w-5 h-5" />
              View Documentation
            </a>
          </div>

          {/* Project Highlights */}
          <div className="grid md:grid-cols-3 gap-6 max-w-4xl mx-auto">
            <div className="bg-white/60 backdrop-blur-sm p-6 rounded-2xl border border-gray-200">
              <div className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                <Shield className="w-6 h-6 text-blue-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">IoT Forensics</h3>
              <p className="text-sm text-gray-600">Memory dump analysis for IoT security investigations</p>
            </div>

            <div className="bg-white/60 backdrop-blur-sm p-6 rounded-2xl border border-gray-200">
              <div className="w-12 h-12 bg-indigo-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                <Cpu className="w-6 h-6 text-indigo-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">Automated Analysis</h3>
              <p className="text-sm text-gray-600">Streamlined workflow using Volatility Framework</p>
            </div>

            <div className="bg-white/60 backdrop-blur-sm p-6 rounded-2xl border border-gray-200">
              <div className="w-12 h-12 bg-purple-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                <Database className="w-6 h-6 text-purple-600" />
              </div>
              <h3 className="font-semibold text-gray-900 mb-2">Open Source</h3>
              <p className="text-sm text-gray-600">Built with modern web technologies</p>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-24 px-6 bg-white">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl lg:text-5xl font-bold text-gray-900 mb-4">
              Key Features
            </h2>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Automated memory forensics workflow designed for IoT security analysis
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            <div className="bg-gradient-to-br from-blue-50 to-indigo-50 p-8 rounded-2xl border border-blue-100">
              <div className="w-14 h-14 bg-white rounded-xl flex items-center justify-center mb-6 shadow-sm">
                <Shield className="w-7 h-7 text-blue-600" />
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Memory Dump Analysis</h3>
              <p className="text-gray-700 leading-relaxed mb-4">
                Upload RAM dumps from IoT devices and extract critical forensic artifacts including running processes, network connections, and loaded modules.
              </p>
              <ul className="space-y-2 text-sm text-gray-600">
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-blue-600 rounded-full mt-2"></div>
                  <span>Process listing and analysis</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-blue-600 rounded-full mt-2"></div>
                  <span>Network connection tracking</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-blue-600 rounded-full mt-2"></div>
                  <span>Loaded kernel modules inspection</span>
                </li>
              </ul>
            </div>

            <div className="bg-gradient-to-br from-purple-50 to-pink-50 p-8 rounded-2xl border border-purple-100">
              <div className="w-14 h-14 bg-white rounded-xl flex items-center justify-center mb-6 shadow-sm">
                <Cpu className="w-7 h-7 text-purple-600" />
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Volatility Integration</h3>
              <p className="text-gray-700 leading-relaxed mb-4">
                Leverages the industry-standard Volatility Framework to perform comprehensive memory forensics with automated plugin execution.
              </p>
              <ul className="space-y-2 text-sm text-gray-600">
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-purple-600 rounded-full mt-2"></div>
                  <span>Automated Volatility 3 plugin execution</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-purple-600 rounded-full mt-2"></div>
                  <span>Linux memory profile support</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-purple-600 rounded-full mt-2"></div>
                  <span>Structured JSON output parsing</span>
                </li>
              </ul>
            </div>

            <div className="bg-gradient-to-br from-green-50 to-emerald-50 p-8 rounded-2xl border border-green-100">
              <div className="w-14 h-14 bg-white rounded-xl flex items-center justify-center mb-6 shadow-sm">
                <Terminal className="w-7 h-7 text-green-600" />
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Web-Based Interface</h3>
              <p className="text-gray-700 leading-relaxed mb-4">
                Modern, responsive web application that simplifies the complex process of memory forensics analysis.
              </p>
              <ul className="space-y-2 text-sm text-gray-600">
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-green-600 rounded-full mt-2"></div>
                  <span>Drag-and-drop file upload</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-green-600 rounded-full mt-2"></div>
                  <span>Real-time analysis progress tracking</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-green-600 rounded-full mt-2"></div>
                  <span>Interactive result visualization</span>
                </li>
              </ul>
            </div>

            <div className="bg-gradient-to-br from-orange-50 to-amber-50 p-8 rounded-2xl border border-orange-100">
              <div className="w-14 h-14 bg-white rounded-xl flex items-center justify-center mb-6 shadow-sm">
                <Database className="w-7 h-7 text-orange-600" />
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Result Management</h3>
              <p className="text-gray-700 leading-relaxed mb-4">
                Store and retrieve analysis results with a clean database schema for historical investigation tracking.
              </p>
              <ul className="space-y-2 text-sm text-gray-600">
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-orange-600 rounded-full mt-2"></div>
                  <span>PostgreSQL database storage</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-orange-600 rounded-full mt-2"></div>
                  <span>Analysis history and metadata</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-orange-600 rounded-full mt-2"></div>
                  <span>Export capabilities for reports</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Tech Stack */}
      <section id="tech" className="py-24 px-6 bg-gradient-to-br from-gray-50 to-slate-100">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl lg:text-5xl font-bold text-gray-900 mb-4">
              Technology Stack
            </h2>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Built with modern, production-ready technologies
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8 mb-12">
            {/* Frontend */}
            <div className="bg-white rounded-2xl p-8 border border-gray-200 shadow-sm">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                  <Code2 className="w-6 h-6 text-blue-600" />
                </div>
                <h3 className="text-xl font-bold text-gray-900">Frontend</h3>
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600">Framework</span>
                  <span className="font-semibold text-gray-900">Next.js 16</span>
                </div>
                <div className="flex items-center justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600">UI Library</span>
                  <span className="font-semibold text-gray-900">React 19</span>
                </div>
                <div className="flex items-center justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600">Styling</span>
                  <span className="font-semibold text-gray-900">Tailwind CSS v4</span>
                </div>
                <div className="flex items-center justify-between py-2">
                  <span className="text-gray-600">Language</span>
                  <span className="font-semibold text-gray-900">TypeScript</span>
                </div>
              </div>
            </div>

            {/* Backend */}
            <div className="bg-white rounded-2xl p-8 border border-gray-200 shadow-sm">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
                  <Database className="w-6 h-6 text-purple-600" />
                </div>
                <h3 className="text-xl font-bold text-gray-900">Backend</h3>
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600">Runtime</span>
                  <span className="font-semibold text-gray-900">Node.js</span>
                </div>
                <div className="flex items-center justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600">Database</span>
                  <span className="font-semibold text-gray-900">PostgreSQL</span>
                </div>
                <div className="flex items-center justify-between py-2 border-b border-gray-100">
                  <span className="text-gray-600">ORM</span>
                  <span className="font-semibold text-gray-900">Prisma</span>
                </div>
                <div className="flex items-center justify-between py-2">
                  <span className="text-gray-600">API</span>
                  <span className="font-semibold text-gray-900">REST API</span>
                </div>
              </div>
            </div>
          </div>

          {/* Forensics Tools */}
          <div className="bg-gradient-to-br from-blue-600 to-indigo-600 rounded-2xl p-8 text-white">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <h3 className="text-xl font-bold">Forensics Engine</h3>
            </div>
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <div className="flex items-center justify-between py-3 border-b border-white/20">
                  <span className="text-blue-100">Core Framework</span>
                  <span className="font-semibold">Volatility 3</span>
                </div>
                <div className="flex items-center justify-between py-3">
                  <span className="text-blue-100">Target Platform</span>
                  <span className="font-semibold">Linux IoT Devices</span>
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between py-3 border-b border-white/20">
                  <span className="text-blue-100">Analysis Type</span>
                  <span className="font-semibold">Memory Forensics</span>
                </div>
                <div className="flex items-center justify-between py-3">
                  <span className="text-blue-100">Output Format</span>
                  <span className="font-semibold">JSON</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 px-6 bg-white">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl lg:text-5xl font-bold text-gray-900 mb-6">
            Try the Analysis Tool
          </h2>
          <p className="text-xl text-gray-600 mb-10">
            Upload a memory dump and explore automated IoT forensics analysis
          </p>
          <Link
            href="/analyze"
            className="inline-flex items-center gap-3 px-10 py-5 bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-lg font-semibold rounded-xl shadow-lg hover:shadow-xl hover:scale-105 transition-all"
          >
            Launch Analysis Console
            <ArrowRight className="w-6 h-6" />
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gradient-to-br from-gray-900 to-slate-900 text-white py-12 px-6 border-t border-gray-800">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="bg-gradient-to-br from-blue-600 to-indigo-600 p-2 rounded-xl">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <span className="text-xl font-bold">PEAT</span>
                <p className="text-sm text-gray-400">Post-Exploitation Analysis Tool</p>
              </div>
            </div>

            <div className="flex items-center gap-6 text-sm text-gray-400">
              <a href="#about" className="hover:text-white transition">About</a>
              <a href="#features" className="hover:text-white transition">Features</a>
              <a href="#tech" className="hover:text-white transition">Tech Stack</a>
              <a href="https://github.com" className="hover:text-white transition flex items-center gap-2">
                <Github className="w-4 h-4" />
                GitHub
              </a>
            </div>
          </div>

          <div className="mt-8 pt-6 border-t border-gray-800 text-center">
            <p className="text-sm text-gray-500">
              Final Year Project 2025 • Built for academic research and IoT security analysis
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
