# WhatsApp Flow Hospital Booking System

A comprehensive WhatsApp Flow endpoint for managing hospital appointment bookings with encrypted interactions, featuring patient registration, appointment scheduling, and secure communication.

## Features

- **Patient Registration**: Support for new and existing patients
- **Appointment Booking**: Doctor and time slot selection  
- **Payment Method Selection**: Private or insurance options
- **Secure Communication**: End-to-end encryption with WhatsApp Flow
- **Multiple Clinics**: Support for various medical specialties
- **Environment-based Configuration**: Secure credential management

## Prerequisites

- Node.js (v16.0.0 or higher)
- npm or yarn package manager
- WhatsApp Business API access
- RSA key pair for encryption

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd whatsapp-flow-tools
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp .env.example .env
```

4. Configure your `.env` file with actual values (see Configuration section below)

## Configuration

### Environment Variables

Create a `.env` file based on `.env.example` and configure the following variables:

#### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `RSA_PASSPHRASE` | Passphrase for RSA private key | `your_secure_passphrase` |
| `RSA_PRIVATE_KEY` | RSA private key for decryption | `-----BEGIN RSA PRIVATE KEY----- ...` |
| `API_BASE_URL` | Base URL for webhook endpoints | `https://your-n8n-instance.domain.com` |
| `API_SIGNUP_ENDPOINT` | Signup webhook path | `/webhook/signup` |
| `API_SIGNIN_ENDPOINT` | Sign-in webhook path | `/webhook/sign_in` |
| `API_BOOKING_ENDPOINT` | Booking submission webhook path | `/webhook/submitbooking` |

#### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `development` |

### RSA Key Setup

1. **Generate RSA Key Pair** (if you don't have one):
```bash
# Generate private key
openssl genrsa -des3 -out private.pem 2048

# Generate public key  
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

2. **Configure WhatsApp Flow**:
   - Upload the public key to WhatsApp Business Manager
   - Add the private key content to `RSA_PRIVATE_KEY` in your `.env` file
   - Set the passphrase in `RSA_PASSPHRASE`

### API Endpoints Setup

Configure your n8n or webhook service with the following endpoints:

- **Signup**: Handles new patient registration
- **Sign-in**: Authenticates existing patients  
- **Booking**: Processes appointment submissions

## Usage

### Development

```bash
npm run dev
```

### Production

```bash
npm start
```

### Flow Structure

The booking flow follows this sequence:

1. **ADMISSION** - Clinic, doctor, date, time, patient type, and payment selection
2. **REGISTRATION** (new patients) - Personal information form
3. **PASIEN** (existing patients) - Sign-in with name/phone and birth date
4. **KONFIRMASI** - Booking confirmation
5. **COMPLETE** - Success screen with booking details

## Security

- All communication is encrypted using RSA + AES-128-GCM
- Environment variables store sensitive credentials
- Private keys are never exposed in code
- The `.env` file is automatically gitignored
- Environment validation ensures all required variables are present

## File Structure

```
whatsapp-flow-tools/
├── hospital booking/
│   └── booking.js          # Main flow endpoint
├── .env                    # Environment variables (gitignored)
├── .env.example           # Environment template
├── .gitignore             # Git ignore rules
├── package.json           # Node.js dependencies
└── README.md             # This file
```

## Environment Variable Validation

The application automatically validates that all required environment variables are present on startup. If any are missing, it will throw a clear error message indicating which variables need to be configured.

## Troubleshooting

### Common Issues

1. **Decryption Errors**:
   - Verify RSA private key format
   - Check passphrase accuracy
   - Ensure key matches WhatsApp public key

2. **API Connectivity**:
   - Verify webhook URLs are accessible
   - Check network connectivity
   - Validate API endpoint responses

3. **Environment Variables**:
   - Ensure `.env` file exists in project root
   - Check for typos in variable names
   - Verify no trailing whitespace in values

### Debug Mode

Set `NODE_ENV=development` to enable detailed logging:

```bash
NODE_ENV=development npm start
```

## Original WhatsApp Flow Payload Processor

This project extends the original WhatsApp Flow payload processor concept with hospital booking functionality.

### Core Functions

- parseIncoming(body): Detects if body contains messages, statuses, or flow action
- normalizeMessages(entries): Flattens to uniform internal message objects  
- buildFlowResponse({ type, data }): Returns object to JSON.stringify for Meta reply
- buildAck(): Minimal 200 OK payload

### Example Integration

```js
// inside an express /webhook POST handler
app.post('/webhook', (req, res) => {
  const responsePayload = processWebhookBody(req.body);
  res.status(200).json(responsePayload);
});
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details
