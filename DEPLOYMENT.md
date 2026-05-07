# SecureShare Vercel Deployment Guide

## 🚀 Deployment Steps

### 1. Backend Deployment (Vercel)

1. Push backend code to GitHub
2. Go to [Vercel Dashboard](https://vercel.com)
3. Click "Add New" → "Project" → Import your GitHub repo
4. Select the `backend` folder as the root directory
5. Go to **Settings** → **Environment Variables** and add:
   - `MONGO_URI` - Your MongoDB connection string
   - `JWT_SECRET` - A secret key for JWT tokens
   - `CLOUDINARY_CLOUD_NAME` - Cloudinary cloud name
   - `CLOUDINARY_API_KEY` - Cloudinary API key
   - `CLOUDINARY_API_SECRET` - Cloudinary API secret
   - `RSA_PUBLIC_KEY` - Your RSA public key
   - `RSA_PRIVATE_KEY` - Your RSA private key

6. Click **Deploy**
7. Note the deployed URL (e.g., `https://secureshare-backend-xyz.vercel.app`)

### 2. Frontend Deployment (Vercel)

1. Go to Vercel Dashboard → "Add New" → "Project" → Import your repo
2. Select the `frontend` folder as the root directory
3. Go to **Settings** → **Environment Variables** and add:
   - `NEXT_PUBLIC_API` = `https://your-backend-vercel-url.vercel.app/api` (use the backend URL from step 1)

4. Click **Deploy**

## ✅ Testing After Deployment

1. Visit your frontend URL
2. Try uploading a file
3. Click "View Logs" on any file
4. The logs should now load without 404 errors

## 🔧 Troubleshooting

### "Failed to load resource: the server responded with a status of 404"

This means the frontend can't reach the backend API. Check:
- [ ] Backend is deployed and running on Vercel
- [ ] `NEXT_PUBLIC_API` environment variable is set in frontend project
- [ ] `NEXT_PUBLIC_API` contains the correct backend URL
- [ ] Backend environment variables are properly set

### Rebuild Frontend After Changing NEXT_PUBLIC_API

After updating environment variables, you must:
1. Trigger a new deployment in Vercel (push a commit, or click "Redeploy")
2. The frontend needs to rebuild with the new env var values

## 📝 Environment Variables Reference

### Backend (.env)
```
MONGO_URI=mongodb+srv://...
JWT_SECRET=your_secret_key
CLOUDINARY_CLOUD_NAME=dalwo0waw
CLOUDINARY_API_KEY=...
CLOUDINARY_API_SECRET=...
RSA_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----...
RSA_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----...
```

### Frontend (.env / Environment Variables)
```
NEXT_PUBLIC_API=https://your-backend.vercel.app/api
```
