'use client';

import { useState } from 'react';
import { Upload, Shield, Zap, Users, FileSearch, CheckCircle } from 'lucide-react';
import Link from 'next/link';

export default function Home() {
  const [isDragging, setIsDragging] = useState(false);

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-200 sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">PEAT</h1>
            </div>
            <nav className="flex gap-6">
              <Link href="#features" className="text-gray-600 hover:text-blue-600 transition">Features</Link>
              <Link href="#how-it-works" className="text-gray-600 hover:text-blue-600 transition">How It Works</Link>
              <Link href="/analyze" className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">Start Analysis</Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-6 py-20">
        <div className="text-center max-w-4xl mx-auto">
          <div className="inline-block bg-blue-100 text-blue-700 px-4 py-2 rounded-full text-sm font-semibold mb-6">
            Post Exploitation Analysis Tool
          </div>
          <h2 className="text-5xl md:text-6xl font-bold text-gray-900 mb-6">
            IoT Forensics Made
            <span className="text-blue-600"> Free & Simple</span>
          </h2>
          <p className="text-xl text-gray-600 mb-8 leading-relaxed">
            Analyze IoT device compromises in seconds. No expensive hardware. No complex setup. Just upload and discover.
          </p>
          <div className="flex gap-4 justify-center">
            <Link 
              href="/analyze"
              className="bg-blue-600 text-white px-8 py-4 rounded-xl font-semibold hover:bg-blue-700 transition shadow-lg hover:shadow-xl transform hover:scale-105"
            >
              Start Free Analysis
            </Link>
            <button className="border-2 border-gray-300 px-8 py-4 rounded-xl font-semibold hover:border-blue-600 hover:text-blue-600 transition">
              Watch Demo
            </button>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-8 mt-16 max-w-2xl mx-auto">
            <div>
              <div className="text-3xl font-bold text-blue-600">₹0</div>
              <div className="text-gray-600 text-sm">Total Cost</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-blue-600">&lt;5s</div>
              <div className="text-gray-600 text-sm">Analysis Time</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-blue-600">∞</div>
              <div className="text-gray-600 text-sm">Concurrent Users</div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="bg-white py-20">
        <div className="container mx-auto px-6">
          <h3 className="text-3xl font-bold text-center mb-12">Why PEAT?</h3>
          <div className="grid md:grid-cols-3 gap-8">
            <FeatureCard
              icon={<Zap className="w-8 h-8" />}
              title="Lightning Fast"
              description="Analyze memory dumps in under 5 seconds. No waiting, no delays."
            />
            <FeatureCard
              icon={<Users className="w-8 h-8" />}
              title="Zero Cost"
              description="Completely free. No subscriptions, no hidden fees. ₹0 forever."
            />
            <FeatureCard
              icon={<FileSearch className="w-8 h-8" />}
              title="Safe Practice"
              description="Generate synthetic scenarios to practice without risk."
            />
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="py-20">
        <div className="container mx-auto px-6">
          <h3 className="text-3xl font-bold text-center mb-12">Simple 3-Step Process</h3>
          <div className="max-w-3xl mx-auto space-y-8">
            <ProcessStep
              number="1"
              title="Upload Memory Dump"
              description="Drop your IoT device memory file or generate practice data"
            />
            <ProcessStep
              number="2"
              title="Automatic Analysis"
              description="Our engine scans for malware, backdoors, and suspicious activities"
            />
            <ProcessStep
              number="3"
              title="Get Results"
              description="View detailed findings with actionable recommendations"
            />
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="bg-gradient-to-r from-blue-600 to-purple-600 py-20">
        <div className="container mx-auto px-6 text-center">
          <h3 className="text-3xl md:text-4xl font-bold text-white mb-6">
            Ready to Analyze Your First IoT Device?
          </h3>
          <p className="text-blue-100 text-lg mb-8 max-w-2xl mx-auto">
            Join students and security professionals using PEAT for IoT forensics.
          </p>
          <Link 
            href="/analyze"
            className="inline-block bg-white text-blue-600 px-8 py-4 rounded-xl font-semibold hover:bg-gray-100 transition shadow-lg"
          >
            Start Free Analysis Now
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-12">
        <div className="container mx-auto px-6 text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-6 h-6" />
            <span className="text-xl font-bold">PEAT</span>
          </div>
          <p className="text-gray-400">
            Making IoT forensics accessible to everyone
          </p>
        </div>
      </footer>
    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="bg-gradient-to-br from-white to-gray-50 p-8 rounded-2xl border border-gray-200 hover:shadow-xl transition">
      <div className="text-blue-600 mb-4">{icon}</div>
      <h4 className="text-xl font-semibold mb-3">{title}</h4>
      <p className="text-gray-600">{description}</p>
    </div>
  );
}

function ProcessStep({ number, title, description }: { number: string; title: string; description: string }) {
  return (
    <div className="flex gap-6 items-start">
      <div className="flex-shrink-0 w-12 h-12 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-xl">
        {number}
      </div>
      <div>
        <h4 className="text-xl font-semibold mb-2">{title}</h4>
        <p className="text-gray-600">{description}</p>
      </div>
    </div>
  );
}
