interface GenKeyPair {
  pair: CryptoKeyPair
  exportKey2Pem: () => Promise<{ pubPem: string; priPem: string }>
}

/**
 * SignEmailPayload is a payload for signing email
 * exp is an optional field for expiration time
 */
export interface SignEmailPayload {
  exp?: number
  email: string
  [key: string]: unknown
}

export async function createKeyPair() {
  const pair = await generateKeyPair()
  const { pubPem, priPem } = await pair.exportKey2Pem()
  return { pubPem, priPem }
}

async function generateKeyPair(): Promise<GenKeyPair> {
  const pair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: 'SHA-256' },
    },
    true,
    ['verify', 'sign']
  )) as CryptoKeyPair
  return { pair, exportKey2Pem } as GenKeyPair
}

async function exportKey2Pem(this: GenKeyPair) {
  const { publicKey, privateKey } = this.pair
  const pubBuffer = (await crypto.subtle.exportKey(
    'spki',
    publicKey
  )) as ArrayBuffer
  const priBuffer = (await crypto.subtle.exportKey(
    'pkcs8',
    privateKey
  )) as ArrayBuffer

  const pubPem = arrayBuffer2Pem(pubBuffer, 'public')
  const priPem = arrayBuffer2Pem(priBuffer, 'private')

  return { pubPem, priPem }
}

export function importKey(
  pem: string,
  type: 'public' | 'private'
): Promise<CryptoKey> {
  const buffer = pem2ArrayBuffer(pem)
  return crypto.subtle.importKey(
    type === 'public' ? 'spki' : 'pkcs8',
    buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    [type === 'public' ? 'verify' : 'sign']
  )
}
/**
 * Like JWT design, header.signature is consist of base64(header).sign(privateKey, payload)
 *
 * data must be JSON string
 */
export async function sign(key: CryptoKey, data: SignEmailPayload) {
  const b64 = btoa(JSON.stringify(data))
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    new TextEncoder().encode(JSON.stringify(data))
  )
  return encodeURIComponent(
    b64 + '.' + btoa(String.fromCharCode(...new Uint8Array(signature)))
  )
}

/**
 * Verify the signature with the public key
 */
interface VerifiedPayload<T> {
  isVerify: true
  payload: T
}

interface UnverifiedPayload {
  isVerify: false
}
export async function verify<T extends SignEmailPayload>(
  key: CryptoKey,
  data: string
): Promise<VerifiedPayload<T> | UnverifiedPayload> {
  const encoder = new TextEncoder()
  const [_, b64, signatureb64] =
    decodeURIComponent(data).match(/([\w\W]+?)\.([\w\W]+)/) ?? []
  if (!b64 || !signatureb64) return { isVerify: false }
  const info = atob(b64)
  const signature = atob(signatureb64)
  const signatureBuffer = new Uint8Array(signature.length)
  signatureBuffer.set([...signature].map((c) => c.charCodeAt(0)))

  const isVerify = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    signatureBuffer,
    encoder.encode(info)
  )
  return isVerify ? { isVerify, payload: JSON.parse(info) as T } : { isVerify }
}

function pem2ArrayBuffer(pem: string) {
  const b64 = pem
    .replace(/-----(?:BEGIN|END) (?:PRIVATE|PUBLIC) KEY-----/g, '')
    .replace(/\s+/g, '')
  const binary = atob(b64)
  const buffer = new Uint8Array(binary.length)
  buffer.set([...binary].map((c) => c.charCodeAt(0)))
  return buffer.buffer
}

function arrayBuffer2Pem(buffer: ArrayBuffer, type: 'public' | 'private') {
  const binary = String.fromCharCode(...new Uint8Array(buffer))
  const b64 = btoa(binary)
  const fmtb64 = b64.match(/.{1,64}/g)?.join('\n') || b64
  const pem = `-----BEGIN ${
    type === 'public' ? 'PUBLIC' : 'PRIVATE'
  } KEY-----\n${fmtb64}\n-----END ${
    type === 'public' ? 'PUBLIC' : 'PRIVATE'
  } KEY-----`
  return pem
}
