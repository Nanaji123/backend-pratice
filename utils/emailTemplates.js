export const verificationEmailTemplate = (name, link) => {
    return `
  <!DOCTYPE html>
  <html>
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Email Verification</title>
    </head>
    <body style="margin:0; padding:0; background-color:#f4f4f4;">
      
      <!-- Outer Wrapper -->
      <table width="100%" cellpadding="0" cellspacing="0" style="padding:30px 0;">
        <tr>
          <td align="center">

            <!-- Main Box -->
            <table width="500" cellpadding="0" cellspacing="0"
              style="
                background:#ffffff;
                border-radius:10px;
                padding:30px;
                box-shadow:0 4px 12px rgba(0,0,0,0.08);
                font-family:Arial, sans-serif;
              ">

              <tr>
                <td align="center">
                  <h2 style="margin:0 0 10px; color:#111;">
                    Verify your email
                  </h2>
                </td>
              </tr>

              <tr>
                <td style="color:#444; font-size:15px; line-height:22px;">
                  <p>Hi <strong>${name}</strong>,</p>
                  <p>
                    Thanks for signing up! Please confirm your email address by
                    clicking the button below.
                  </p>
                </td>
              </tr>

              <!-- Button -->
              <tr>
                <td align="center" style="padding:25px 0;">
                  <a href="${link}"
                    style="
                      background-color:#4f46e5;
                      color:#ffffff !important;
                      text-decoration:none;
                      padding:14px 28px;
                      border-radius:6px;
                      font-weight:bold;
                      font-size:15px;
                      display:inline-block;
                    ">
                    Verify Email
                  </a>
                </td>
              </tr>

              <tr>
                <td style="color:#555; font-size:14px;">
                  <p>
                    If you didn’t create this account, you can safely ignore this email.
                  </p>
                </td>
              </tr>

              <tr>
                <td style="border-top:1px solid #eee; padding-top:15px; font-size:12px; color:#777;">
                  <p>
                    This verification link will expire in <strong>1 hour</strong>.
                  </p>
                </td>
              </tr>

            </table>
            <!-- End Box -->

          </td>
        </tr>
      </table>

    </body>
  </html>
  `;
};

export const passwordResetEmailTemplate = (name, link) => {
    return `
  <!DOCTYPE html>
  <html>
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Password Reset</title>
    </head>
    <body style="margin:0; padding:0; background-color:#f4f4f4;">
      
      <!-- Outer Wrapper -->
      <table width="100%" cellpadding="0" cellspacing="0" style="padding:30px 0;">
        <tr>
          <td align="center">

            <!-- Main Box -->
            <table width="500" cellpadding="0" cellspacing="0"
              style="
                background:#ffffff;
                border-radius:10px;
                padding:30px;
                box-shadow:0 4px 12px rgba(0,0,0,0.08);
                font-family:Arial, sans-serif;
              ">

              <tr>
                <td align="center">
                  <h2 style="margin:0 0 10px; color:#111;">
                    Reset your password
                  </h2>
                </td>
              </tr>

              <tr>
                <td style="color:#444; font-size:15px; line-height:22px;">
                  <p>Hi <strong>${name}</strong>,</p>
                  <p>
                    We received a request to reset your password. Click the button below to choose a new one.
                  </p>
                </td>
              </tr>

              <!-- Button -->
              <tr>
                <td align="center" style="padding:25px 0;">
                  <a href="${link}"
                    style="
                      background-color:#4f46e5;
                      color:#ffffff !important;
                      text-decoration:none;
                      padding:14px 28px;
                      border-radius:6px;
                      font-weight:bold;
                      font-size:15px;
                      display:inline-block;
                    ">
                    Reset Password
                  </a>
                </td>
              </tr>

              <tr>
                <td style="color:#555; font-size:14px;">
                  <p>
                    If you didn’t request this, you can safely ignore this email.
                  </p>
                </td>
              </tr>

              <tr>
                <td style="border-top:1px solid #eee; padding-top:15px; font-size:12px; color:#777;">
                  <p>
                    This reset link will expire in <strong>15 minutes</strong>.
                  </p>
                </td>
              </tr>

            </table>
            <!-- End Box -->

          </td>
        </tr>
      </table>

    </body>
  </html>
  `;
};
