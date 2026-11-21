import { useEffect, useState } from 'react';
import QRCode from 'qrcode';

interface QrCodeDisplayProps {
  value: string;
  label: string;
  caption?: string;
  size?: number;
}

export function QrCodeDisplay({ value, label, caption, size = 148 }: QrCodeDisplayProps) {
  const [dataUrl, setDataUrl] = useState<string>('');
  const [error, setError] = useState<string>('');

  useEffect(() => {
    let active = true;
    QRCode.toDataURL(value, {
      width: size * 2,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: {
        dark: '#0f172a',
        light: '#ffffff',
      },
    })
      .then((url) => {
        if (active) {
          setDataUrl(url);
          setError('');
        }
      })
      .catch(() => {
        if (active) setError('No se pudo generar el código QR');
      });
    return () => {
      active = false;
    };
  }, [value, size]);

  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-slate-200 bg-white p-3">
      {error ? (
        <div
          className="flex items-center justify-center rounded bg-slate-100 text-xs text-slate-500"
          style={{ width: size, height: size }}
        >
          {error}
        </div>
      ) : dataUrl ? (
        <img
          src={dataUrl}
          alt={label}
          width={size}
          height={size}
          className="block rounded border border-slate-100"
        />
      ) : (
        <div
          className="animate-pulse rounded bg-slate-100"
          style={{ width: size, height: size }}
        />
      )}
      <div className="w-full text-center">
        <p className="text-xs font-semibold text-slate-800">{label}</p>
        {caption && (
          <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500" title={value}>
            {caption}
          </p>
        )}
      </div>
    </div>
  );
}
