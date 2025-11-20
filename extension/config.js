// LPH Password Manager - Supabase Configuration
// This file contains your Supabase project credentials

export const SUPABASE_CONFIG = {
  // Your Supabase Project URL
  url: 'https://bnpctvuhdlfxycoeryhu.supabase.co',
  
  // Your Supabase Anonymous (Public) Key
  // This key is safe to expose in client-side code
  // It only works with Row Level Security (RLS) policies
  anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJucGN0dnVoZGxmeHljb2VyeWh1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjIyMzQ5NjMsImV4cCI6MjA3NzgxMDk2M30.cH9c1HvNWA04SFiZvuNlQFzHEA6W8BLmelME73sLqQ8'
};

// ✅ Configuration is complete and ready to use!
// 
// SECURITY NOTES:
// - The anon key is safe to use in client-side code
// - Row Level Security (RLS) ensures users can only access their own data
// - NEVER use the 'service_role' key in client-side code
// - Your master password and decrypted data never reach Supabase
// - Only encrypted blobs are stored in the database
//
// NEXT STEPS:
// 1. Save this file as: extension/config.js
// 2. Make sure you've created the database tables (see QUICKSTART.md)
// 3. Update manifest.json to include config.js in web_accessible_resources
// 4. Reload your extension in Chrome
// 5. Test by signing up and syncing passwords