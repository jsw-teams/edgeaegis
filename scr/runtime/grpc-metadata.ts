const trailers = new WeakMap<Response, Promise<Headers>>();

export function setGrpcTrailers(response: Response, value: Promise<Headers>) {
  trailers.set(response, value);
  return response;
}

export function getGrpcTrailers(response: Response) {
  return trailers.get(response);
}

export function copyGrpcTrailers(from: Response, to: Response) {
  const value = trailers.get(from);
  if (value) trailers.set(to, value);
  return to;
}
