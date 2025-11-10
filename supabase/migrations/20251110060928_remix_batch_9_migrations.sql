
-- Migration: 20251018060726
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum for user roles
CREATE TYPE public.app_role AS ENUM ('user', 'admin');

-- User roles table
CREATE TABLE public.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    role app_role NOT NULL DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (user_id, role)
);

-- Enable RLS
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- Security definer function to check roles
CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role app_role)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id AND role = _role
  )
$$;

-- Profiles table
CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT,
    avatar_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view all profiles"
ON public.profiles FOR SELECT
USING (true);

CREATE POLICY "Users can update own profile"
ON public.profiles FOR UPDATE
USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile"
ON public.profiles FOR INSERT
WITH CHECK (auth.uid() = id);

-- Tourist spots table
CREATE TABLE public.tourist_spots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    contact_number TEXT,
    location TEXT NOT NULL,
    municipality TEXT,
    category TEXT[] DEFAULT '{}',
    image_url TEXT,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    rating DECIMAL(3, 2) DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.tourist_spots ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view tourist spots"
ON public.tourist_spots FOR SELECT
USING (true);

CREATE POLICY "Only admins can insert tourist spots"
ON public.tourist_spots FOR INSERT
WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Only admins can update tourist spots"
ON public.tourist_spots FOR UPDATE
USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Only admins can delete tourist spots"
ON public.tourist_spots FOR DELETE
USING (public.has_role(auth.uid(), 'admin'));

-- Restaurants table
CREATE TABLE public.restaurants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    food_type TEXT,
    location TEXT NOT NULL,
    municipality TEXT,
    description TEXT,
    image_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.restaurants ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view restaurants"
ON public.restaurants FOR SELECT
USING (true);

CREATE POLICY "Only admins can manage restaurants"
ON public.restaurants FOR ALL
USING (public.has_role(auth.uid(), 'admin'));

-- Events and Festivals table
CREATE TABLE public.events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    event_type TEXT,
    location TEXT NOT NULL,
    municipality TEXT,
    description TEXT,
    event_date DATE,
    image_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view events"
ON public.events FOR SELECT
USING (true);

CREATE POLICY "Only admins can manage events"
ON public.events FOR ALL
USING (public.has_role(auth.uid(), 'admin'));

-- User itineraries table
CREATE TABLE public.itineraries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL DEFAULT 'My Itinerary',
    selected_categories TEXT[] DEFAULT '{}',
    spots JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.itineraries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own itineraries"
ON public.itineraries FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can create own itineraries"
ON public.itineraries FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own itineraries"
ON public.itineraries FOR UPDATE
USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own itineraries"
ON public.itineraries FOR DELETE
USING (auth.uid() = user_id);

-- Reviews table
CREATE TABLE public.reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    spot_id UUID REFERENCES public.tourist_spots(id) ON DELETE CASCADE NOT NULL,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.reviews ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view reviews"
ON public.reviews FOR SELECT
USING (true);

CREATE POLICY "Authenticated users can create reviews"
ON public.reviews FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own reviews"
ON public.reviews FOR UPDATE
USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own reviews"
ON public.reviews FOR DELETE
USING (auth.uid() = user_id);

-- Function to handle new user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE PLPGSQL
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name)
  VALUES (new.id, new.raw_user_meta_data->>'full_name');
  
  INSERT INTO public.user_roles (user_id, role)
  VALUES (new.id, 'user');
  
  RETURN new;
END;
$$;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER update_profiles_updated_at
BEFORE UPDATE ON public.profiles
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_tourist_spots_updated_at
BEFORE UPDATE ON public.tourist_spots
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_itineraries_updated_at
BEFORE UPDATE ON public.itineraries
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Migration: 20251023014556
-- Add RLS policies for user_roles table to prevent privilege escalation
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- Users can view their own roles
CREATE POLICY "Users can view own roles"
ON public.user_roles
FOR SELECT
TO authenticated
USING (auth.uid() = user_id);

-- Only admins can view all roles
CREATE POLICY "Admins can view all roles"
ON public.user_roles
FOR SELECT
TO authenticated
USING (has_role(auth.uid(), 'admin'));

-- Only admins can insert roles
CREATE POLICY "Admins can insert roles"
ON public.user_roles
FOR INSERT
TO authenticated
WITH CHECK (has_role(auth.uid(), 'admin'));

-- Only admins can update roles
CREATE POLICY "Admins can update roles"
ON public.user_roles
FOR UPDATE
TO authenticated
USING (has_role(auth.uid(), 'admin'));

-- Only admins can delete roles
CREATE POLICY "Admins can delete roles"
ON public.user_roles
FOR DELETE
TO authenticated
USING (has_role(auth.uid(), 'admin'));

-- Migration: 20251024011616
-- Add bio column to profiles table
ALTER TABLE public.profiles
ADD COLUMN bio TEXT;

-- Migration: 20251102131835
-- Add missing fields to tourist_spots table
ALTER TABLE public.tourist_spots ADD COLUMN IF NOT EXISTS is_hidden_gem BOOLEAN DEFAULT false;

-- Add onboarding_answers to profiles table
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS onboarding_answers JSONB;

-- Update itineraries table to include route
ALTER TABLE public.itineraries DROP COLUMN IF EXISTS route;
ALTER TABLE public.itineraries ADD COLUMN route JSONB DEFAULT '{"start":"","destinations":[],"total_distance":"","estimated_time":""}'::jsonb;

-- Create index for hidden gems query performance
CREATE INDEX IF NOT EXISTS idx_tourist_spots_hidden_gem ON public.tourist_spots(is_hidden_gem) WHERE is_hidden_gem = true;

-- Migration: 20251104035859
-- Add user_preferences column to profiles table
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS user_preferences JSONB;

-- Add index for faster queries on user preferences
CREATE INDEX IF NOT EXISTS idx_profiles_user_preferences ON public.profiles USING gin(user_preferences);

-- Migration: 20251105111343
-- Create accommodations table for hotels and lodging
CREATE TABLE public.accommodations (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  location TEXT NOT NULL,
  municipality TEXT,
  category TEXT[] DEFAULT '{}',
  image_url TEXT,
  contact_number TEXT,
  email TEXT,
  price_range TEXT,
  amenities TEXT[] DEFAULT '{}',
  rating NUMERIC DEFAULT 0,
  latitude NUMERIC,
  longitude NUMERIC,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.accommodations ENABLE ROW LEVEL SECURITY;

-- Allow anyone to view accommodations (public data)
CREATE POLICY "Anyone can view accommodations"
ON public.accommodations
FOR SELECT
USING (true);

-- Only admins can manage accommodations
CREATE POLICY "Only admins can manage accommodations"
ON public.accommodations
FOR ALL
USING (has_role(auth.uid(), 'admin'::app_role));

-- Add trigger for updated_at
CREATE TRIGGER update_accommodations_updated_at
BEFORE UPDATE ON public.accommodations
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Add some sample data
INSERT INTO public.accommodations (name, description, location, municipality, category, price_range, amenities, rating) VALUES
('The Oriental Legazpi', 'Premium hotel with stunning views of Mayon Volcano and modern amenities', 'Rizal Street, Old Albay District', 'Legazpi', ARRAY['Luxury', 'Business Hotel', 'City Center'], '₱3,500 - ₱8,000', ARRAY['WiFi', 'Restaurant', 'Pool', 'Gym', 'Conference Rooms', 'Spa'], 4.5),
('Mayon Backpackers Hostel', 'Budget-friendly hostel for solo travelers and backpackers', 'Penaranda Street', 'Legazpi', ARRAY['Budget', 'Hostel', 'Backpacker'], '₱300 - ₱800', ARRAY['WiFi', 'Common Area', 'Kitchen', 'Lockers'], 4.2),
('Misibis Bay Resort', 'Luxury beachfront resort with private island experience', 'Misibis Bay', 'Cagraray Island', ARRAY['Luxury', 'Beach Resort', 'All-Inclusive'], '₱12,000 - ₱30,000', ARRAY['WiFi', 'Beach Access', 'Water Sports', 'Restaurant', 'Spa', 'Pool', 'Bar'], 4.8),
('Hotel St. Ellis', 'Comfortable mid-range hotel near city attractions', 'Penaranda Street', 'Legazpi', ARRAY['Mid-range', 'City Center', 'Family-Friendly'], '₱1,500 - ₱3,000', ARRAY['WiFi', 'Restaurant', 'Air Conditioning', 'Cable TV'], 4.0),
('Pepperland Hotel', 'Modern boutique hotel with artistic interiors', 'Tahao Road', 'Legazpi', ARRAY['Mid-range', 'Boutique', 'Pet-Friendly'], '₱2,000 - ₱4,500', ARRAY['WiFi', 'Restaurant', 'Parking', 'Pet-Friendly', 'Art Gallery'], 4.3),
('Tiwi Hot Spring Resort', 'Natural hot spring resort for relaxation', 'Tiwi Hot Springs', 'Tiwi', ARRAY['Resort', 'Hot Springs', 'Nature'], '₱1,800 - ₱5,000', ARRAY['Hot Springs', 'Restaurant', 'Pool', 'Massage', 'Nature Trails'], 4.4),
('Casa Simeon', 'Heritage house turned boutique hotel', 'Brgy. Banao', 'Guinobatan', ARRAY['Boutique', 'Heritage', 'Mountain View'], '₱2,500 - ₱4,000', ARRAY['WiFi', 'Restaurant', 'Garden', 'Mountain View', 'Cultural Tours'], 4.6),
('Albay Astoria Hotel', 'Value hotel for business and leisure travelers', 'Washington Drive', 'Legazpi', ARRAY['Mid-range', 'Business Hotel'], '₱1,800 - ₱3,500', ARRAY['WiFi', 'Restaurant', 'Meeting Rooms', 'Parking'], 4.1);

-- Migration: 20251106050850
-- Create temp_otps table for OTP verification
CREATE TABLE IF NOT EXISTS public.temp_otps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  contact TEXT NOT NULL,
  otp_code TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  verified BOOLEAN DEFAULT false
);

-- Add trigger to auto-delete expired OTPs
CREATE OR REPLACE FUNCTION delete_expired_otps()
RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM public.temp_otps
  WHERE created_at < now() - interval '5 minutes';
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER cleanup_expired_otps
  BEFORE INSERT ON public.temp_otps
  FOR EACH ROW
  EXECUTE FUNCTION delete_expired_otps();

-- Enable RLS
ALTER TABLE public.temp_otps ENABLE ROW LEVEL SECURITY;

-- Allow anyone to insert OTPs
CREATE POLICY "Anyone can insert OTPs"
  ON public.temp_otps
  FOR INSERT
  WITH CHECK (true);

-- Allow users to read their own OTPs
CREATE POLICY "Users can read their own OTPs"
  ON public.temp_otps
  FOR SELECT
  USING (true);

-- Allow users to update their own OTPs
CREATE POLICY "Users can update their own OTPs"
  ON public.temp_otps
  FOR UPDATE
  USING (true);

-- Create favorites table
CREATE TABLE IF NOT EXISTS public.favorites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  item_id UUID NOT NULL,
  item_type TEXT NOT NULL CHECK (item_type IN ('spot', 'restaurant', 'event', 'accommodation')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE (user_id, item_id, item_type)
);

-- Enable RLS on favorites
ALTER TABLE public.favorites ENABLE ROW LEVEL SECURITY;

-- Users can view their own favorites
CREATE POLICY "Users can view own favorites"
  ON public.favorites
  FOR SELECT
  USING (auth.uid() = user_id);

-- Users can create their own favorites
CREATE POLICY "Users can create own favorites"
  ON public.favorites
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Users can delete their own favorites
CREATE POLICY "Users can delete own favorites"
  ON public.favorites
  FOR DELETE
  USING (auth.uid() = user_id);

-- Update profiles table to add onboarding_complete
ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS onboarding_complete BOOLEAN DEFAULT false;

-- Migration: 20251106051017
-- Fix search_path for delete_expired_otps function
CREATE OR REPLACE FUNCTION delete_expired_otps()
RETURNS TRIGGER 
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  DELETE FROM public.temp_otps
  WHERE created_at < now() - interval '5 minutes';
  RETURN NEW;
END;
$$;

-- Fix search_path for update_updated_at_column function
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER 
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

-- Migration: 20251107163517
-- Create categories table
CREATE TABLE IF NOT EXISTS public.categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  icon TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create subcategories table
CREATE TABLE IF NOT EXISTS public.subcategories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category_id UUID REFERENCES public.categories(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subcategories ENABLE ROW LEVEL SECURITY;

-- RLS Policies for categories
CREATE POLICY "Anyone can view categories"
ON public.categories
FOR SELECT
USING (true);

CREATE POLICY "Admins can manage categories"
ON public.categories
FOR ALL
USING (has_role(auth.uid(), 'admin'::app_role))
WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

-- RLS Policies for subcategories
CREATE POLICY "Anyone can view subcategories"
ON public.subcategories
FOR SELECT
USING (true);

CREATE POLICY "Admins can manage subcategories"
ON public.subcategories
FOR ALL
USING (has_role(auth.uid(), 'admin'::app_role))
WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

-- Add district to events table
ALTER TABLE public.events
ADD COLUMN IF NOT EXISTS district TEXT;

-- Create notifications table
CREATE TABLE IF NOT EXISTS public.notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  event_id UUID REFERENCES public.events(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  is_read BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS on notifications
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

-- RLS Policies for notifications
CREATE POLICY "Users can view own notifications"
ON public.notifications
FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can update own notifications"
ON public.notifications
FOR UPDATE
USING (auth.uid() = user_id);

CREATE POLICY "System can create notifications"
ON public.notifications
FOR INSERT
WITH CHECK (true);

-- Insert default categories
INSERT INTO public.categories (name, icon) VALUES
  ('Nature', '🌿'),
  ('Food', '🍴'),
  ('Culture', '🎭'),
  ('Beach', '🏖️'),
  ('Adventure', '🧗')
ON CONFLICT DO NOTHING;

-- Insert default subcategories (getting category IDs first)
INSERT INTO public.subcategories (category_id, name, description)
SELECT c.id, sub.name, sub.description
FROM public.categories c
CROSS JOIN (
  VALUES
    ('Nature', 'Waterfalls', 'Beautiful cascading waterfalls'),
    ('Nature', 'Volcanoes', 'Active and dormant volcanoes'),
    ('Nature', 'Lakes', 'Scenic lakes and lagoons'),
    ('Nature', 'Scenic Parks', 'Nature parks and gardens'),
    ('Food', 'Street Food', 'Local street food vendors'),
    ('Food', 'Local Cuisine', 'Traditional Bicolano dishes'),
    ('Food', 'Cafés', 'Coffee shops and cafés'),
    ('Food', 'Night Markets', 'Evening food markets'),
    ('Culture', 'Festivals', 'Local celebrations and festivals'),
    ('Culture', 'Churches', 'Historic churches and cathedrals'),
    ('Culture', 'Museums', 'Cultural and historical museums'),
    ('Culture', 'Crafts', 'Traditional crafts and artisans'),
    ('Beach', 'Island Hopping', 'Visit nearby islands'),
    ('Beach', 'Snorkeling', 'Underwater exploration'),
    ('Beach', 'Resorts', 'Beach resorts and accommodations'),
    ('Beach', 'Sunset Views', 'Best spots for sunsets'),
    ('Adventure', 'Hiking', 'Mountain and trail hiking'),
    ('Adventure', 'ATV Rides', 'All-terrain vehicle adventures'),
    ('Adventure', 'Ziplines', 'Thrilling zipline experiences'),
    ('Adventure', 'Caving', 'Cave exploration')
) AS sub(category_name, name, description)
WHERE c.name = sub.category_name
ON CONFLICT DO NOTHING;
