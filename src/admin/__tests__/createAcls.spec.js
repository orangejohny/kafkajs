const createAdmin = require('../index')

const {
  secureRandom,
  createCluster,
  newLogger,
  sslConnectionOpts,
  saslBrokers,
} = require('testHelpers')

const RESOURCE_TYPES = require('../../protocol/resourceTypes')
const OPERATION_TYPES = require('../../protocol/operationsTypes')
const PERMISSION_TYPES = require('../../protocol/permissionTypes')
const RESOURCE_PATTERN_TYPES = require('../../protocol/resourcePatternTypes')

const createSASLAdminClientForUser = ({ username, password }) => {
  const saslConnectionOpts = () =>
    Object.assign(sslConnectionOpts(), {
      port: 9094,
      sasl: {
        mechanism: 'plain',
        username,
        password,
      },
    })
  const admin = createAdmin({
    cluster: createCluster(saslConnectionOpts(), saslBrokers()),
    logger: newLogger(),
  })
  return admin
}

describe('Admin', () => {
  let admin

  afterEach(async () => {
    await admin.disconnect()
  })

  describe('createAcls', () => {
    test('throws an error if the acl array is invalid', async () => {
      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      await expect(admin.createAcls({ acl: 'this-is-not-an-array' })).rejects.toHaveProperty(
        'message',
        'Invalid ACL array this-is-not-an-array'
      )
    })

    test('throws an error if the resource name is invalid', async () => {
      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      const ACLEntry = {
        resourceType: RESOURCE_TYPES.TOPIC,
        resourceName: 123,
        resourcePatternType: RESOURCE_PATTERN_TYPES.LITERAL,
        principal: 'User:foo',
        host: '*',
        operation: OPERATION_TYPES.ALL,
        permissionType: PERMISSION_TYPES.DENY,
      }

      await expect(admin.createAcls({ acl: [ACLEntry] })).rejects.toHaveProperty(
        'message',
        'Invalid ACL array, the resourceNames have to be a valid string'
      )
    })

    test('throws an error if the principal name is invalid', async () => {
      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      const ACLEntry = {
        resourceType: RESOURCE_TYPES.TOPIC,
        resourceName: 'foo',
        resourcePatternType: RESOURCE_PATTERN_TYPES.LITERAL,
        principal: 123,
        host: '*',
        operation: OPERATION_TYPES.ALL,
        permissionType: PERMISSION_TYPES.DENY,
      }

      await expect(admin.createAcls({ acl: [ACLEntry] })).rejects.toHaveProperty(
        'message',
        'Invalid ACL array, the principals have to be a valid string'
      )
    })

    test('throws an error if the host name is invalid', async () => {
      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      const ACLEntry = {
        resourceType: RESOURCE_TYPES.TOPIC,
        resourceName: 'foo',
        resourcePatternType: RESOURCE_PATTERN_TYPES.LITERAL,
        principal: 'User:foo',
        host: 123,
        operation: OPERATION_TYPES.ALL,
        permissionType: PERMISSION_TYPES.DENY,
      }

      await expect(admin.createAcls({ acl: [ACLEntry] })).rejects.toHaveProperty(
        'message',
        'Invalid ACL array, the hosts have to be a valid string'
      )
    })

    test('throws an error if there are invalid resource types', async () => {
      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      const ACLEntry = {
        resourceType: 123,
        resourceName: 'foo',
        resourcePatternType: RESOURCE_PATTERN_TYPES.LITERAL,
        principal: 'User:foo',
        host: '*',
        operation: OPERATION_TYPES.ALL,
        permissionType: PERMISSION_TYPES.DENY,
      }

      await expect(admin.createAcls({ acl: [ACLEntry] })).rejects.toHaveProperty(
        'message',
        `Invalid resource type 123: ${JSON.stringify(ACLEntry)}`
      )
    })

    test('throws an error if there are invalid resource pattern types', async () => {
      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      const ACLEntry = {
        resourceType: RESOURCE_TYPES.TOPIC,
        resourceName: 'foo',
        resourcePatternType: 123,
        principal: 'User:foo',
        host: '*',
        operation: OPERATION_TYPES.ALL,
        permissionType: PERMISSION_TYPES.DENY,
      }

      await expect(admin.createAcls({ acl: [ACLEntry] })).rejects.toHaveProperty(
        'message',
        `Invalid resource pattern type 123: ${JSON.stringify(ACLEntry)}`
      )
    })

    test('throws an error if there are invalid permission types', async () => {
      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      const ACLEntry = {
        resourceType: RESOURCE_TYPES.TOPIC,
        resourceName: 'foo',
        resourcePatternType: RESOURCE_PATTERN_TYPES.LITERAL,
        principal: 'User:foo',
        host: '*',
        operation: OPERATION_TYPES.ALL,
        permissionType: 123,
      }

      await expect(admin.createAcls({ acl: [ACLEntry] })).rejects.toHaveProperty(
        'message',
        `Invalid permission type 123: ${JSON.stringify(ACLEntry)}`
      )
    })

    test('throws an error if there are invalid operation types', async () => {
      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      const ACLEntry = {
        resourceType: RESOURCE_TYPES.TOPIC,
        resourceName: 'foo',
        resourcePatternType: RESOURCE_PATTERN_TYPES.LITERAL,
        principal: 'User:foo',
        host: '*',
        operation: 123,
        permissionType: PERMISSION_TYPES.DENY,
      }

      await expect(admin.createAcls({ acl: [ACLEntry] })).rejects.toHaveProperty(
        'message',
        `Invalid operation type 123: ${JSON.stringify(ACLEntry)}`
      )
    })

    test('checks topic access', async () => {
      const topicName = `test-topic-${secureRandom()}`

      admin = createSASLAdminClientForUser({ username: 'test', password: 'testtest' })
      await admin.connect()

      await expect(
        admin.createTopics({
          waitForLeaders: true,
          topics: [{ topic: topicName, numPartitions: 1, replicationFactor: 2 }],
        })
      ).resolves.toEqual(true)

      await expect(
        admin.createAcls({
          acl: [
            {
              resourceType: RESOURCE_TYPES.TOPIC,
              resourceName: topicName,
              resourcePatternType: RESOURCE_PATTERN_TYPES.LITERAL,
              principal: 'User:bob',
              host: '*',
              operation: OPERATION_TYPES.ALL,
              permissionType: PERMISSION_TYPES.DENY,
            },
            {
              resourceType: RESOURCE_TYPES.TOPIC,
              resourceName: topicName,
              resourcePatternType: RESOURCE_PATTERN_TYPES.LITERAL,
              principal: 'User:alice',
              host: '*',
              operation: OPERATION_TYPES.ALL,
              permissionType: PERMISSION_TYPES.ALLOW,
            },
          ],
        })
      ).resolves.toEqual(true)

      admin = createSASLAdminClientForUser({ username: 'bob', password: 'bobbob' })
      await admin.connect()

      await expect(admin.getTopicMetadata({ topics: [topicName] })).rejects.toThrow(
        'Not authorized to access topics: [Topic authorization failed]'
      )

      admin = createSASLAdminClientForUser({ username: 'alice', password: 'alicealice' })
      await admin.connect()

      await expect(admin.getTopicMetadata({ topics: [topicName] })).resolves.toBeTruthy()
    })
  })
})
