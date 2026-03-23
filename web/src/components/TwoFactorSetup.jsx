import { useState } from 'react';
import { Shield, ShieldCheck, ShieldOff, Loader2 } from 'lucide-react';
import api from '../api/axios';
import toast from 'react-hot-toast';

export default function TwoFactorSetup({ enabled, onStatusChange }) {
  const [qrCode, setQrCode] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState('idle'); // idle | setup | verify

  const handleSetup = async () => {
    setLoading(true);
    try {
      const res = await api.post('/api/auth/2fa/setup');
      setQrCode(res.data.qrCode || res.data.qr || '');
      setStep('verify');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to setup 2FA');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    if (!verificationCode.trim() || verificationCode.length < 6) {
      toast.error('Please enter a valid 6-digit code');
      return;
    }
    setLoading(true);
    try {
      await api.post('/api/auth/2fa/verify', { code: verificationCode });
      toast.success('2FA enabled successfully');
      setStep('idle');
      setVerificationCode('');
      setQrCode('');
      if (onStatusChange) onStatusChange(true);
    } catch (err) {
      toast.error(err.response?.data?.message || 'Invalid code');
    } finally {
      setLoading(false);
    }
  };

  const handleDisable = async () => {
    if (!window.confirm('Are you sure you want to disable 2FA?')) return;
    setLoading(true);
    try {
      await api.post('/api/auth/2fa/disable');
      toast.success('2FA disabled');
      if (onStatusChange) onStatusChange(false);
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to disable 2FA');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-4 bg-white dark:bg-gray-800 rounded-2xl border border-slate-200 dark:border-gray-700">
      <div className="flex items-center gap-2 mb-4">
        <Shield className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
        <h3 className="text-base font-semibold text-slate-800 dark:text-white">Two-Factor Authentication</h3>
      </div>

      {/* Status */}
      <div className="flex items-center gap-2 mb-4 p-3 bg-slate-50 dark:bg-gray-700 rounded-xl">
        {enabled ? (
          <>
            <ShieldCheck className="w-5 h-5 text-green-500" />
            <span className="text-sm font-medium text-green-700 dark:text-green-400">2FA is enabled</span>
          </>
        ) : (
          <>
            <ShieldOff className="w-5 h-5 text-slate-400" />
            <span className="text-sm font-medium text-slate-500 dark:text-gray-400">2FA is not enabled</span>
          </>
        )}
      </div>

      {step === 'idle' && (
        <button
          onClick={enabled ? handleDisable : handleSetup}
          disabled={loading}
          className={`w-full py-2.5 text-sm font-medium rounded-xl transition-colors disabled:opacity-50 ${
            enabled
              ? 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/30'
              : 'bg-indigo-600 text-white hover:bg-indigo-700'
          }`}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading...
            </span>
          ) : enabled ? 'Disable 2FA' : 'Enable 2FA'}
        </button>
      )}

      {step === 'verify' && (
        <div className="space-y-4">
          {qrCode && (
            <div className="flex justify-center p-4 bg-white rounded-xl">
              <img src={qrCode} alt="2FA QR Code" className="w-48 h-48" />
            </div>
          )}
          <p className="text-sm text-slate-600 dark:text-gray-400 text-center">
            Scan the QR code with your authenticator app, then enter the 6-digit code.
          </p>
          <input
            type="text"
            value={verificationCode}
            onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            placeholder="Enter 6-digit code"
            maxLength={6}
            className="w-full px-4 py-3 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-center text-lg font-mono text-slate-800 dark:text-gray-200 tracking-widest focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
          />
          <div className="flex gap-2">
            <button
              onClick={() => { setStep('idle'); setQrCode(''); setVerificationCode(''); }}
              className="flex-1 py-2.5 bg-slate-100 dark:bg-gray-700 text-slate-600 dark:text-gray-300 text-sm font-medium rounded-xl hover:bg-slate-200 dark:hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              onClick={handleVerify}
              disabled={loading || verificationCode.length < 6}
              className="flex-1 py-2.5 bg-indigo-600 text-white text-sm font-medium rounded-xl hover:bg-indigo-700 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify & Enable'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
