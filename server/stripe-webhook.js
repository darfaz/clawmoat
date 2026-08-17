class StripeWebhookError extends Error {
  constructor(message, { statusCode, publicMessage, cause } = {}) {
    super(message, { cause });
    this.name = 'StripeWebhookError';
    this.statusCode = statusCode;
    this.publicMessage = publicMessage;
  }
}

function parseStripeWebhook({ rawBody, signature, endpointSecret, stripe }) {
  if (!signature) {
    throw new StripeWebhookError('Stripe signature header is missing', {
      statusCode: 400,
      publicMessage: 'Missing Stripe signature',
    });
  }

  if (!endpointSecret) {
    throw new StripeWebhookError('Stripe webhook signing secret is not configured', {
      statusCode: 503,
      publicMessage: 'Webhook endpoint is not configured',
    });
  }

  try {
    return stripe.webhooks.constructEvent(rawBody, signature, endpointSecret);
  } catch (error) {
    throw new StripeWebhookError('Stripe webhook signature verification failed', {
      statusCode: 400,
      publicMessage: 'Invalid Stripe signature',
      cause: error,
    });
  }
}

module.exports = {
  StripeWebhookError,
  parseStripeWebhook,
};
