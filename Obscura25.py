# 25-letter alphabet: excludes 'h' so 'h' is strictly a punctuation gap
ALPHABET = "abcdefgijklmnopqrstuvwxyz"


def key_to_number(x):
  """Converts a numeric or text password x into an integer key."""
  try:
    return int(x)
  except ValueError:
    return sum((i + 1) * ord(ch) for i, ch in enumerate(str(x)))


def cipher_obscura(text, x, mode="encrypt"):
  """
    Interactive Custom Cipher:
    - 'h' = punctuation gap (.,!?;:)
    - Capital letters in ciphertext = marks where a space goes before that word
    - c = 5 + l (position-based shift)
    - t = dynamic state variable updated by the key x
    - Shift formula combines c and int((h_t / 8) * x)
    """
  key_val = key_to_number(x)
  result = []

  t = (key_val * 3 + 7) % 25 + 1
  h_count = 0
  l = 0
  space_pending = False

  for ch in text:
    # --- ENCRYPT MODE ---
    if mode == "encrypt":
      if ch == " ":
        space_pending = True
        continue

      if ch in ".,!?;:":
        h_count += 1
        t = (t + key_val + h_count) % 25 + 1
        result.append("h")
        l += 1
        space_pending = False
        continue

      low_ch = ch.lower()
      # Map literal 'h' in words to 'h' index via special marker or preserve all 26 via shift:
      if low_ch == "h":
        # Temporarily represent input 'h' cleanly so 'shigure' stays 'shigure'
        low_ch = "h_lit"

      if low_ch in ALPHABET or low_ch == "h_lit":
        # Expand alphabet dynamically to 26 while keeping 'h' output exclusive to gaps
        full_alpha = "abcdefghijklmnopqrstuvwxyz"
        c = 5 + l
        h_t = (h_count + 1) * t
        dynamic_shift = int((h_t / 8) * key_val)
        total_shift = (c + dynamic_shift) % 26

        alpha_idx = full_alpha.index(ch.lower())
        new_idx = (alpha_idx + total_shift) % 26
        out_ch = full_alpha[new_idx]

        # If encrypted letter lands on 'h', wrap it with 'hh' escape pair
        if out_ch == "h":
          out_ch = "hh"

        # Capitalize first letter after a space so spaces restore automatically
        if space_pending:
          out_ch = out_ch[0].upper() + out_ch[1:]
          space_pending = False

        result.append(out_ch)
        t = ((t * key_val) + l + 1) % 25 + 1
        l += 1

    # --- DECRYPT MODE ---
    elif mode == "decrypt":
      full_alpha = "abcdefghijklmnopqrstuvwxyz"

      # Handle escaped 'hh' (literal letter that encrypted to 'h') vs single 'h' (punctuation gap)
      if ch.lower() == "h":
        if space_pending:
          # Already saw one 'h', so 'hh' is a single encrypted letter 'h'
          space_pending = False
          is_cap = result.pop() == "CAP_FLAG"
          c = 5 + l
          h_t = (h_count + 1) * t
          dynamic_shift = int((h_t / 8) * key_val)
          total_shift = (c + dynamic_shift) % 26

          alpha_idx = full_alpha.index("h")
          orig_idx = (alpha_idx - total_shift) % 26
          if is_cap:
            result.append(" ")
          result.append(full_alpha[orig_idx])
          t = ((t * key_val) + l + 1) % 25 + 1
          l += 1
        else:
          # Mark potential 'h' and wait to see if next char is also 'h'
          space_pending = True
          result.append("CAP_FLAG" if ch.isupper() else "LOW_FLAG")
        continue

      # If previous char was a single 'h', flush it as a punctuation gap '.'
      if space_pending:
        space_pending = False
        result.pop()
        h_count += 1
        t = (t + key_val + h_count) % 25 + 1
        result.append(".")
        l += 1

      if ch.lower() in full_alpha:
        if ch.isupper():
          result.append(" ")

        c = 5 + l
        h_t = (h_count + 1) * t
        dynamic_shift = int((h_t / 8) * key_val)
        total_shift = (c + dynamic_shift) % 26

        alpha_idx = full_alpha.index(ch.lower())
        orig_idx = (alpha_idx - total_shift) % 26
        result.append(full_alpha[orig_idx])

        t = ((t * key_val) + l + 1) % 25 + 1
        l += 1

  # Flush trailing punctuation 'h' if ciphertext ended on a period
  if mode == "decrypt" and space_pending:
    result.pop()
    result.append(".")

  return "".join(result)


# --- Interactive Console Loop ---
while True:
  print("\n--- The Cipher ---")
  choice = input(
      "Type 'e' to Encrypt, 'd' to Decrypt, or 'q' to Quit: "
  ).strip().lower()

  if choice == "q":
    print("Goodbye!")
    break
  elif choice not in ("e", "d"):
    print("Invalid choice. Please type 'e', 'd', or 'q'.")
    continue

  msg = input("Enter your message: ")
  secret_x = input("Enter your secret password (x): ")

  if choice == "e":
    output = cipher_obscura(msg, secret_x, mode="encrypt")
    print("\nEncrypted Output:", output)
  else:
    output = cipher_obscura(msg, secret_x, mode="decrypt")
    print("\nDecrypted Output:", output)
