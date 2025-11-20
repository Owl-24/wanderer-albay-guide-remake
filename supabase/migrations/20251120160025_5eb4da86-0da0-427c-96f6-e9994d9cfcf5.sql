-- Add spot_type column to tourist_spots table
ALTER TABLE public.tourist_spots 
ADD COLUMN spot_type TEXT[] DEFAULT '{}';