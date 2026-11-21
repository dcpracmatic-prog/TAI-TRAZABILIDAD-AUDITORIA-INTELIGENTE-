declare module 'react-qr-scanner' {
  import type { ComponentType, VideoHTMLAttributes } from 'react';

  export interface QrScannerResult {
    text?: string;
    rawBytes?: Uint8Array;
    numBits?: number;
    resultPoints?: Array<{ x: number; y: number }>;
    format?: number;
    timestamp?: number;
    canvas?: HTMLCanvasElement;
  }

  export interface QrScannerProps
    extends Omit<VideoHTMLAttributes<HTMLVideoElement>, 'onError' | 'onLoad'> {
    constraints?: MediaStreamConstraints;
    onScan: (data: QrScannerResult | string | null) => void;
    onError: (error: unknown) => void;
    onLoad?: () => void;
    resolution?: number;
    qrArea?: [number, number] | [];
    delay?: number | false;
    facingMode?: 'front' | 'rear';
    legacyMode?: boolean;
  }

  const QrScanner: ComponentType<QrScannerProps>;
  export default QrScanner;
}
