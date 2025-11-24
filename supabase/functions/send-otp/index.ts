import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { Resend } from 'https://esm.sh/resend@4.0.0';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.75.1';

const resend = new Resend(Deno.env.get("RESEND_API_KEY"));

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface SendOTPRequest {
  contact: string;
  contactType: 'email' | 'phone';
}

const handler = async (req: Request): Promise<Response> => {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { contact, contactType }: SendOTPRequest = await req.json();

    console.log(`OTP request for ${contactType}: ${contact}`);

    // Validate input
    if (!contact || !contactType) {
      throw new Error('Contact and contactType are required');
    }

    // Basic validation
    if (contactType === 'email') {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(contact)) {
        throw new Error('Invalid email format');
      }
    } else if (contactType === 'phone') {
      const phoneRegex = /^\+63[0-9]{10}$/;
      if (!phoneRegex.test(contact)) {
        throw new Error('Invalid phone format. Use +63XXXXXXXXXX');
      }
    }

    // Initialize Supabase client
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    );

    // Check if user already exists in auth
    const { data: existingUsers } = await supabaseClient.auth.admin.listUsers();
    const userExists = existingUsers?.users.some(user => 
      user.email === contact || user.phone === contact
    );

    if (userExists) {
      return new Response(
        JSON.stringify({ 
          error: 'An account with this email or phone already exists. Please login instead.' 
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    }

    // Generate 6-digit OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    console.log(`Generated OTP: ${otpCode} for ${contact}`);

    // Delete any existing unverified OTPs for this contact
    await supabaseClient
      .from('temp_otps')
      .delete()
      .eq('contact', contact)
      .eq('verified', false);

    // Store OTP in database
    const { error: dbError } = await supabaseClient
      .from('temp_otps')
      .insert({
        contact,
        otp_code: otpCode,
        verified: false,
      });

    if (dbError) {
      console.error('Database error:', dbError);
      throw new Error('Failed to store OTP');
    }

    // Send OTP based on contact type
    if (contactType === 'email') {
      console.log(`Sending email to: ${contact}`);
      
      const { error: emailError } = await resend.emails.send({
        from: "Wanderer Albay <onboarding@resend.dev>",
        to: [contact],
        subject: "Your Wanderer Albay Verification Code",
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #333; margin-bottom: 10px;">🌋 Welcome to Wanderer Albay!</h1>
              <p style="color: #666; font-size: 16px;">Explore the beauty of Albay with us</p>
            </div>
            
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 20px;">
              <p style="color: white; font-size: 14px; margin-bottom: 10px;">Your verification code is:</p>
              <h2 style="color: white; font-size: 36px; letter-spacing: 8px; margin: 0; font-weight: bold;">${otpCode}</h2>
            </div>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px;">
              <p style="font-size: 14px; color: #666; margin: 0;">
                <strong>⏰ This code will expire in 5 minutes.</strong>
              </p>
              <p style="font-size: 14px; color: #666; margin-top: 10px;">
                Enter this code to complete your registration and start exploring tourist spots in Albay.
              </p>
            </div>
            
            <p style="font-size: 12px; color: #999; text-align: center;">
              If you didn't request this code, please ignore this email.
            </p>
          </div>
        `,
      });

      if (emailError) {
        console.error('Email error:', emailError);
        throw new Error('Failed to send email');
      }

      console.log('Email sent successfully');
    } else if (contactType === 'phone') {
      // Phone SMS functionality
      // Note: This requires an SMS provider like Twilio to be configured
      // For now, return an error indicating SMS is not supported
      return new Response(
        JSON.stringify({ 
          error: 'SMS verification is currently not available. Please use email instead.' 
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    }

    return new Response(
      JSON.stringify({ 
        success: true, 
        message: "OTP sent successfully",
        expiresIn: 300 // 5 minutes in seconds
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  } catch (error: any) {
    console.error("Error in send-otp:", error);
    return new Response(
      JSON.stringify({ 
        error: error.message || 'Failed to send OTP. Please try again.' 
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  }
};

serve(handler);
