export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "13.0.5"
  }
  public: {
    Tables: {
      accommodations: {
        Row: {
          amenities: string[] | null
          category: string[] | null
          contact_number: string | null
          created_at: string
          description: string | null
          email: string | null
          id: string
          image_url: string | null
          latitude: number | null
          location: string
          longitude: number | null
          municipality: string | null
          name: string
          price_range: string | null
          rating: number | null
          updated_at: string
        }
        Insert: {
          amenities?: string[] | null
          category?: string[] | null
          contact_number?: string | null
          created_at?: string
          description?: string | null
          email?: string | null
          id?: string
          image_url?: string | null
          latitude?: number | null
          location: string
          longitude?: number | null
          municipality?: string | null
          name: string
          price_range?: string | null
          rating?: number | null
          updated_at?: string
        }
        Update: {
          amenities?: string[] | null
          category?: string[] | null
          contact_number?: string | null
          created_at?: string
          description?: string | null
          email?: string | null
          id?: string
          image_url?: string | null
          latitude?: number | null
          location?: string
          longitude?: number | null
          municipality?: string | null
          name?: string
          price_range?: string | null
          rating?: number | null
          updated_at?: string
        }
        Relationships: []
      }
      categories: {
        Row: {
          created_at: string | null
          icon: string | null
          id: string
          name: string
        }
        Insert: {
          created_at?: string | null
          icon?: string | null
          id?: string
          name: string
        }
        Update: {
          created_at?: string | null
          icon?: string | null
          id?: string
          name?: string
        }
        Relationships: []
      }
      events: {
        Row: {
          created_at: string
          description: string | null
          district: string | null
          event_date: string | null
          event_type: string | null
          id: string
          image_url: string | null
          location: string
          municipality: string | null
          name: string
        }
        Insert: {
          created_at?: string
          description?: string | null
          district?: string | null
          event_date?: string | null
          event_type?: string | null
          id?: string
          image_url?: string | null
          location: string
          municipality?: string | null
          name: string
        }
        Update: {
          created_at?: string
          description?: string | null
          district?: string | null
          event_date?: string | null
          event_type?: string | null
          id?: string
          image_url?: string | null
          location?: string
          municipality?: string | null
          name?: string
        }
        Relationships: []
      }
      favorites: {
        Row: {
          created_at: string | null
          id: string
          item_id: string
          item_type: string
          user_id: string
        }
        Insert: {
          created_at?: string | null
          id?: string
          item_id: string
          item_type: string
          user_id: string
        }
        Update: {
          created_at?: string | null
          id?: string
          item_id?: string
          item_type?: string
          user_id?: string
        }
        Relationships: []
      }
      itineraries: {
        Row: {
          created_at: string
          id: string
          name: string
          route: Json | null
          selected_categories: string[] | null
          spots: Json | null
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          name?: string
          route?: Json | null
          selected_categories?: string[] | null
          spots?: Json | null
          updated_at?: string
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          name?: string
          route?: Json | null
          selected_categories?: string[] | null
          spots?: Json | null
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      notifications: {
        Row: {
          created_at: string | null
          event_id: string | null
          id: string
          is_read: boolean | null
          message: string
          user_id: string | null
        }
        Insert: {
          created_at?: string | null
          event_id?: string | null
          id?: string
          is_read?: boolean | null
          message: string
          user_id?: string | null
        }
        Update: {
          created_at?: string | null
          event_id?: string | null
          id?: string
          is_read?: boolean | null
          message?: string
          user_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "notifications_event_id_fkey"
            columns: ["event_id"]
            isOneToOne: false
            referencedRelation: "events"
            referencedColumns: ["id"]
          },
        ]
      }
      profiles: {
        Row: {
          avatar_url: string | null
          bio: string | null
          created_at: string
          full_name: string | null
          id: string
          onboarding_answers: Json | null
          onboarding_complete: boolean | null
          updated_at: string
          user_preferences: Json | null
        }
        Insert: {
          avatar_url?: string | null
          bio?: string | null
          created_at?: string
          full_name?: string | null
          id: string
          onboarding_answers?: Json | null
          onboarding_complete?: boolean | null
          updated_at?: string
          user_preferences?: Json | null
        }
        Update: {
          avatar_url?: string | null
          bio?: string | null
          created_at?: string
          full_name?: string | null
          id?: string
          onboarding_answers?: Json | null
          onboarding_complete?: boolean | null
          updated_at?: string
          user_preferences?: Json | null
        }
        Relationships: []
      }
      restaurants: {
        Row: {
          created_at: string
          description: string | null
          food_type: string | null
          id: string
          image_url: string | null
          location: string
          municipality: string | null
          name: string
        }
        Insert: {
          created_at?: string
          description?: string | null
          food_type?: string | null
          id?: string
          image_url?: string | null
          location: string
          municipality?: string | null
          name: string
        }
        Update: {
          created_at?: string
          description?: string | null
          food_type?: string | null
          id?: string
          image_url?: string | null
          location?: string
          municipality?: string | null
          name?: string
        }
        Relationships: []
      }
      reviews: {
        Row: {
          comment: string | null
          created_at: string
          id: string
          rating: number
          spot_id: string
          user_id: string
        }
        Insert: {
          comment?: string | null
          created_at?: string
          id?: string
          rating: number
          spot_id: string
          user_id: string
        }
        Update: {
          comment?: string | null
          created_at?: string
          id?: string
          rating?: number
          spot_id?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "reviews_spot_id_fkey"
            columns: ["spot_id"]
            isOneToOne: false
            referencedRelation: "tourist_spots"
            referencedColumns: ["id"]
          },
        ]
      }
      subcategories: {
        Row: {
          category_id: string | null
          created_at: string | null
          description: string | null
          id: string
          name: string
        }
        Insert: {
          category_id?: string | null
          created_at?: string | null
          description?: string | null
          id?: string
          name: string
        }
        Update: {
          category_id?: string | null
          created_at?: string | null
          description?: string | null
          id?: string
          name?: string
        }
        Relationships: [
          {
            foreignKeyName: "subcategories_category_id_fkey"
            columns: ["category_id"]
            isOneToOne: false
            referencedRelation: "categories"
            referencedColumns: ["id"]
          },
        ]
      }
      temp_otps: {
        Row: {
          contact: string
          created_at: string | null
          id: string
          otp_code: string
          verified: boolean | null
        }
        Insert: {
          contact: string
          created_at?: string | null
          id?: string
          otp_code: string
          verified?: boolean | null
        }
        Update: {
          contact?: string
          created_at?: string | null
          id?: string
          otp_code?: string
          verified?: boolean | null
        }
        Relationships: []
      }
      tourist_spots: {
        Row: {
          category: string[] | null
          contact_number: string | null
          created_at: string
          description: string | null
          id: string
          image_url: string | null
          is_hidden_gem: boolean | null
          latitude: number | null
          location: string
          longitude: number | null
          municipality: string | null
          name: string
          rating: number | null
          spot_type: string[] | null
          updated_at: string
        }
        Insert: {
          category?: string[] | null
          contact_number?: string | null
          created_at?: string
          description?: string | null
          id?: string
          image_url?: string | null
          is_hidden_gem?: boolean | null
          latitude?: number | null
          location: string
          longitude?: number | null
          municipality?: string | null
          name: string
          rating?: number | null
          spot_type?: string[] | null
          updated_at?: string
        }
        Update: {
          category?: string[] | null
          contact_number?: string | null
          created_at?: string
          description?: string | null
          id?: string
          image_url?: string | null
          is_hidden_gem?: boolean | null
          latitude?: number | null
          location?: string
          longitude?: number | null
          municipality?: string | null
          name?: string
          rating?: number | null
          spot_type?: string[] | null
          updated_at?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "user" | "admin"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["user", "admin"],
    },
  },
} as const
