const test = require('node:test');
const assert = require('node:assert/strict');

const { parseStripeWebhook } = require('../server/stripe-webhook');

test('rejects webhook requests without a Stripe signature', () => {
  const stripe = {
    webhooks: {
      constructEvent() {
        throw new Error('constructEvent must not be called without a signature');
      },
    },
  };

  assert.throws(
    () => parseStripeWebhook({
      rawBody: Buffer.from('{"type":"diagnostic.ping"}'),
      signature: undefined,
      endpointSecret: 'whsec_test',
      stripe,
    }),
    (error) => error.statusCode === 400 && error.publicMessage === 'Missing Stripe signature'
  );
});

test('rejects webhook requests when the signing secret is not configured', () => {
  const stripe = {
    webhooks: {
      constructEvent() {
        throw new Error('constructEvent must not be called without a signing secret');
      },
    },
  };

  assert.throws(
    () => parseStripeWebhook({
      rawBody: Buffer.from('{"type":"diagnostic.ping"}'),
      signature: 't=1,v1=test',
      endpointSecret: undefined,
      stripe,
    }),
    (error) => error.statusCode === 503 && error.publicMessage === 'Webhook endpoint is not configured'
  );
});

test('maps Stripe signature verification failures to a safe client error', () => {
  const verificationFailure = new Error('No signatures found matching the expected signature');
  const stripe = {
    webhooks: {
      constructEvent() {
        throw verificationFailure;
      },
    },
  };

  assert.throws(
    () => parseStripeWebhook({
      rawBody: Buffer.from('{"type":"diagnostic.ping"}'),
      signature: 't=1,v1=invalid',
      endpointSecret: 'whsec_test',
      stripe,
    }),
    (error) => (
      error.statusCode === 400
      && error.publicMessage === 'Invalid Stripe signature'
      && error.cause === verificationFailure
    )
  );
});
