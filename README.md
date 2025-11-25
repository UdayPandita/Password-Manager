# LPH Password Manager

## Overview

LPH Password Manager is a secure, Electron-based password management application featuring an extension-style user interface and a lightweight backend server architecture. The application provides enterprise-grade encryption and secure credential storage capabilities.

## Prerequisites

- **Node.js**: Version 14 or higher is recommended for optimal performance
- **npm**: Package manager (bundled with Node.js installation)
- **Electron**: Framework dependency (automatically installed via `npm install`)

## Quick Start

### Installation

Install all required dependencies:

```bash
npm install
```

### Launch Application

Start the password manager:

```bash
npm start
```

The application launches via `main.js` (entry point) and renders the primary interface through `index.html`.

## User Guide

### Initial Setup

**New Users:**
- Complete the signup process to create your account
- Securely store the generated mnemonic phrases (required for account recovery)
- Verify your mnemonic phrases to confirm account creation

**Existing Users:**
- Sign in using your credentials to access the password manager

### Core Features

#### Password Management
- **Add Password**: Securely store credentials for websites and applications
- **View Passwords**: Access and manage your stored credentials within the vault

#### Secure Password Sharing
- **Share Functionality**: Securely share credentials with trusted users registered on the platform
- **Encryption Protocol**: Passwords are encrypted using the recipient's public key, providing protection against Man-in-the-Middle (MITM) attacks
- **Recipient Experience**: Recipients can decrypt received passwords using their private key and optionally add them to their vault

#### Security Controls
- **Lock Feature**: Prevents unauthorized access and protects against shoulder surfing when stepping away from your device
- **Account Security**: Monitor your account for potential security breaches
- **Settings**:
  - Change master password for enhanced security
  - Data wipe functionality for complete account removal

### Security Architecture

#### RSA-OAEP Key Pair Generation
- Upon initial signup, a public-private key pair is generated using RSA-OAEP encryption (2048-bit modulus, SHA-256 hash)
- **Public Key**: Encrypts passwords during the sharing process
- **Private Key**: Decrypts received passwords (encrypted with vault key at rest)

#### Account Recovery Security
- If account recovery is performed, new RSA keys are automatically generated
- Previously shared passwords become undecryptable, protecting the sender if mnemonic phrases are compromised
- This prevents unauthorized access through account recovery mechanisms

#### Mnemonic Phrase System
- **Purpose**: Secure account recovery mechanism
- **Advantages**:
  - Not susceptible to interception (unlike OTP-based systems)
  - Resistant to brute-force attacks
  - User-friendly recovery process without requiring external communication channels

#### Vault Lock Protection
- Protects credentials from shoulder surfing attacks
- Prevents unauthorized access when devices are left unattended
- Requires re-authentication to unlock the vault


## Video Demonstration

For a comprehensive walkthrough of the password manager's features and functionality, please view our demonstration video:

**[Watch Demo Video](https://drive.google.com/file/d/1GDjbqAlx9ob9xUhHaffe0lTICGCubjpB/view?usp=sharing)**

## Troubleshooting

### Common Issues

**Application fails to start (`npm start`)**
- Verify Node.js and npm are properly installed
- Ensure `node_modules` directory exists (run `npm install` if missing)
- Check that all dependencies are installed correctly

**Electron-related errors**
- Review error messages for missing modules or version mismatches
- Verify `devDependencies` in `package.json`
- Perform a clean reinstall: `npm ci`

**Resource loading failures**
- Check browser console for 404 errors indicating missing resources
- Verify relative path configurations in extension pages
- Confirm working directory used by `main.js` for file loading operations
