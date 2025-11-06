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
        .single();

      if (otpError || !otpData) {
        throw new Error('Invalid verification code');
      }

      // Check if OTP is expired (5 minutes)
      const createdAt = new Date(otpData.created_at);
      const now = new Date();
      const diffMinutes = (now.getTime() - createdAt.getTime()) / (1000 * 60);

      if (diffMinutes > 5) {
        throw new Error('Verification code has expired');
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
        },
      });

      if (authError) throw authError;

      // Mark OTP as verified
      await supabase
        .from('temp_otps')
        .update({ verified: true })
        .eq('id', otpData.id);

      // Clear signup data
      sessionStorage.removeItem('signup_data');

      toast.success('Account created successfully!');
      navigate('/dashboard');
    } catch (error: any) {
      console.error('OTP verification error:', error);
      toast.error(error.message || 'Failed to verify code');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleResendOTP = async () => {
    try {
      const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/send-otp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contact: signupData.contact,
          contactType: signupData.contactType,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to resend OTP');
      }

      toast.success('New verification code sent!');
      setOtp('');
    } catch (error: any) {
      console.error('Resend OTP error:', error);
      toast.error(error.message || 'Failed to resend code');
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
