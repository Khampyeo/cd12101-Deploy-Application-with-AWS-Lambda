import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import { createLogger } from '../../utils/logger.mjs'
import { getUserId } from '../utils.mjs'
import { saveImgUrl } from '../../dataLayer/todosAccess.mjs'
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3"
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'

const bucketName = process.env.S3_BUCKET
const urlExpiration = Number(process.env.SIGNED_URL_EXPIRATION)
const logger = createLogger('generateUploadUrl')
const client = new S3Client({ region: "us-east-1" });

export const handler = middy()
  .use(httpErrorHandler())
  .use(
    cors({
      credentials: true
    })
  )
  .handler(async (event) => {
    const todoId = event.pathParameters.todoId

    logger.info('Generating upload URL:', {
      todoId,
      bucketName
    })
    const userId = getUserId(event)
    const command = new PutObjectCommand({Bucket: bucketName, Key: todoId });
    const uploadUrl = await getSignedUrl(client, command, { expiresIn: urlExpiration })

    logger.info('Generating upload URL:', {
      todoId,
      uploadUrl
    })

    await saveImgUrl(userId, todoId, bucketName)

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        uploadUrl: uploadUrl
      })
    }
  })