import axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const jwksUrl = 'https://dev-i04d5brxhm1zdum1.us.auth0.com/.well-known/jwks.json'

export async function handler(event) {
  try { 
    console.log("auth: step 1");
    console.log("Authorization Token:", event.authorizationToken);
    
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  console.log("auth: step 2");

  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })
  console.log("auth: step 3");

  try {
    console.log("auth: get jwks");
    const res = await axios.get(jwksUrl)
    console.log("auth: step 4");
    
    const key = res?.data?.keys?.find((k) => k.kid === jwt.header.kid)
    if (!key) {
      throw new Error('Key not found')
    }
    const pem = key.x5c[0]
    const cert = `-----BEGIN CERTIFICATE-----\n${pem}\n-----END CERTIFICATE-----`
    console.log(cert);
    console.log("auth: step 5");
    return jsonwebtoken.verify(token, cert)
  } catch (error) {
    logger.error('Token verification failed', { error: JSON.stringify(error) });  }

  return undefined;
}

function getToken(authHeader) {
  console.log("auth: getToken");
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
