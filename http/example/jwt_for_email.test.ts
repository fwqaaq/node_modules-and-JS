import { verify } from './jwt_for_email.ts'
import { createKeyPair, importKey, sign } from './jwt_for_email.ts'
import { expect } from 'jsr:@std/expect'

async function main() {
  const { pubPem, priPem } = await createKeyPair()

  const pub = await importKey(pubPem, 'public')
  const pri = await importKey(priPem, 'private')

  const signature = await sign(pri, { exp: 1000, email: 'xxx@gmail.com' })
  const isVaild = await verify(pub, signature)

  // test
  expect(isVaild.isVerify).toBe(true)
}

Deno.test('test', main)
