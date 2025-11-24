import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { toast } from "sonner";
import { Loader2 } from "lucide-react";

export default function VerifyOTP() {
  const navigate = useNavigate();
  const [otp, setOtp] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);
  const [signupData, setSignupData] = useState<any>(null);

  useEffect(() => {
    const data = sessionStorage.getItem('signup_data');
    if (!data) {
      toast.error('No signup data found. Please sign up first.');
      navigate('/signup');
      return;
    }
    setSignupData(JSON.parse(data));
  }, [navigate]);

  const handleVerifyOTP = async () => {
    if (otp.length !== 6) {
      toast.error('Please enter a 6-digit code');
      return;
    }

    setIsVerifying(true);

    try {
      // Verify OTP from database
      const { data: otpData, error: otpError } = await supabase
        .from('temp_otps')
        .select('*')
        .eq('contact', signupData.contact)
        .eq('otp_code', otp)
        .eq('verified', false)
        .maybeSingle();

      if (otpError || !otpData) {
        throw new Error('Invalid or expired verification code. Please try again.');
      }

      // Check if OTP is expired (5 minutes)
      const createdAt = new Date(otpData.created_at);
      const now = new Date();
      const diffMinutes = (now.getTime() - createdAt.getTime()) / (1000 * 60);

      if (diffMinutes > 5) {
        throw new Error('Verification code has expired. Please request a new one.');
      }

      // Check if account already exists
      const { data: { user: existingUser }, error: checkError } = await supabase.auth.getUser();
      
      if (existingUser?.email === signupData.contact) {
        throw new Error('An account with this email already exists. Please login instead.');
      }

      // Create Supabase account
      const { data: authData, error: authError } = await supabase.auth.signUp({
        email: signupData.contactType === 'email' ? signupData.contact : `${signupData.contact}@placeholder.com`,
        password: signupData.password,
        options: {
          data: {
            full_name: signupData.fullName,
            phone: signupData.contactType === 'phone' ? signupData.contact : null,
          },
          emailRedirectTo: `${window.location.origin}/`,
        },
      });

      if (authError) {
        if (authError.message.includes('already registered')) {
          throw new Error('An account with this email already exists. Please login instead.');
        }
        throw authError;
      }

      // Mark OTP as verified
      await supabase
        .from('temp_otps')
        .update({ verified: true })
        .eq('id', otpData.id);

      // Clear signup data
      sessionStorage.removeItem('signup_data');

      toast.success('Account created successfully! Welcome to Wanderer!');
      
      // Navigate to homepage
      setTimeout(() => {
        navigate('/');
      }, 500);
    } catch (error: any) {
      console.error('OTP verification error:', error);
      toast.error(error.message || 'Failed to verify code. Please try again.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleResendOTP = async () => {
    try {
      const response = await supabase.functions.invoke('send-otp', {
        body: {
          contact: signupData.contact,
          contactType: signupData.contactType,
        },
      });

      if (response.error) {
        throw new Error(response.error.message || 'Failed to resend OTP');
      }

      toast.success('New verification code sent!');
      setOtp('');
    } catch (error: any) {
      console.error('Resend OTP error:', error);
      toast.error(error.message || 'Failed to resend code. Please try again.');
    }
  };

  if (!signupData) {
    return null;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary/10 via-background to-secondary/10 p-4">
      <Card className="w-full max-w-md animate-fade-in">
        <CardHeader className="space-y-1 text-center">
          <div className="mx-auto mb-4 text-6xl">🔐</div>
          <CardTitle className="text-2xl font-bold">Verify Your Account</CardTitle>
          <CardDescription>
            Enter the 6-digit code sent to{" "}
            <span className="font-semibold">{signupData.contact}</span>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex justify-center">
            <InputOTP
              maxLength={6}
              value={otp}
              onChange={setOtp}
              onComplete={handleVerifyOTP}
            >
              <InputOTPGroup>
                <InputOTPSlot index={0} />
                <InputOTPSlot index={1} />
                <InputOTPSlot index={2} />
                <InputOTPSlot index={3} />
                <InputOTPSlot index={4} />
                <InputOTPSlot index={5} />
              </InputOTPGroup>
            </InputOTP>
          </div>

          <Button
            onClick={handleVerifyOTP}
            className="w-full"
            disabled={isVerifying || otp.length !== 6}
          >
            {isVerifying ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Verifying...
              </>
            ) : (
              'Verify Code'
            )}
          </Button>

          <div className="text-center space-y-2">
            <p className="text-sm text-muted-foreground">
              Didn't receive the code?
            </p>
            <Button
              type="button"
              variant="link"
              onClick={handleResendOTP}
              className="p-0 h-auto"
            >
              Resend Code
            </Button>
          </div>

          <Button
            variant="outline"
            className="w-full"
            onClick={() => {
              sessionStorage.removeItem('signup_data');
              navigate('/signup');
            }}
          >
            Back to Sign Up
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
