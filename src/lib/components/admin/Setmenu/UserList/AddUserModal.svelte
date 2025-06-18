<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { createEventDispatcher } from 'svelte';
	import { onMount, getContext } from 'svelte';
	import { addUser } from '$lib/apis/setmenu';

	import { WEBUI_BASE_URL } from '$lib/constants';
	import Switch from '$lib/components/common/Switch.svelte';
	import Modal from '$lib/components/common/Modal.svelte';
	import { generateInitialsImage } from '$lib/utils';

	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();

	export let show = false;

	let loading = false;
	let tab = '';
	let inputFiles;

	let _user = {
		id: '',
		name: '',
		description: '',
		price: null,
		credits: null,
		duration: null,
		is_active: true
	};

	$: if (show) {
		_user = {
			id: '',
			name: '',
			description: '',
			price: null,
			credits: null,
			duration: null,
			is_active: true
		};
	}

	const submitHandler = async () => {
		console.log('创建套餐', _user);

		const stopLoading = () => {
			dispatch('save');
			loading = false;
		};

		if (tab === '') {
			loading = true;
			const res = await addUser(
				localStorage.token,
				_user.id,
				_user.name,
				_user.description,
				_user.price,
				_user.duration,
				_user.is_active,
				_user.credits
			).catch((error) => {
				toast.error(`${error}`);
			});

			if (res) {
				stopLoading();
				show = false;
			}
		} else {
			if (inputFiles) {
				loading = true;

				const file = inputFiles[0];
				const reader = new FileReader();

				reader.onload = async (e) => {
					const csv = e.target.result;
					const rows = csv.split('\n');

					let userCount = 0;

					for (const [idx, row] of rows.entries()) {
						const columns = row.split(',').map((col) => col.trim());
						console.log(idx, columns);

						if (idx > 0) {
							if (
								columns.length === 4 &&
								['admin', 'user', 'pending'].includes(columns[3].toLowerCase())
							) {
								const res = await addUser(
									localStorage.token,
									columns[0],
									columns[1],
									columns[2],
									columns[3].toLowerCase(),
									generateInitialsImage(columns[0])
								).catch((error) => {
									toast.error(`Row ${idx + 1}: ${error}`);
									return null;
								});

								if (res) {
									userCount = userCount + 1;
								}
							} else {
								toast.error(`Row ${idx + 1}: invalid format.`);
							}
						}
					}

					toast.success(`Successfully imported ${userCount} users.`);
					inputFiles = null;
					const uploadInputElement = document.getElementById('upload-user-csv-input');

					if (uploadInputElement) {
						uploadInputElement.value = null;
					}

					stopLoading();
				};

				reader.readAsText(file, 'utf-8');
			} else {
				toast.error($i18n.t('File not found.'));
			}
		}

		loading = false;
	};
</script>

<Modal size="sm" bind:show>
	<div>
		<div class=" flex justify-between dark:text-gray-300 px-5 pt-4 pb-2">
			<div class=" text-lg font-medium self-center">{$i18n.t('addmenu')}</div>
			<button
				class="self-center"
				on:click={() => {
					show = false;
				}}
			>
				<svg
					xmlns="http://www.w3.org/2000/svg"
					viewBox="0 0 20 20"
					fill="currentColor"
					class="w-5 h-5"
				>
					<path
						d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"
					/>
				</svg>
			</button>
		</div>

		<div class="flex flex-col md:flex-row w-full px-4 pb-3 md:space-x-4 dark:text-gray-200">
			<div class=" flex flex-col w-full sm:flex-row sm:justify-center sm:space-x-6">
				<form
					class="flex flex-col w-full"
					on:submit|preventDefault={() => {
						submitHandler();
					}}
				>
					<div class="px-1">
						{#if tab === ''}
							<!-- <div class="flex flex-col w-full my-2">
							<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuname')}</div>

							<div class="flex-1">
								<input
									class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
									type="text"
									bind:value={_user.id}
									placeholder={$i18n.t('menuname_placeholder')}
									autocomplete="off"
									required
								/>
							</div>
						</div> -->
							<div class="flex flex-col w-full my-2">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuname')}</div>

								<div class="flex-1">
									<input
										class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										type="text"
										bind:value={_user.name}
										placeholder={$i18n.t('menuname_placeholder')}
										autocomplete="off"
										required
									/>
								</div>
							</div>

							<hr class=" border-gray-100 dark:border-gray-850 my-2.5 w-full" />

							<div class="flex flex-col w-full">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menudescription')}</div>

								<div class="flex-1">
									<textarea
										class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										bind:value={_user.description}
										placeholder={$i18n.t('menudescription_placeholder')}
										required
									/>
								</div>
							</div>

							<div class="flex flex-col w-full my-2">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuduration')}</div>

								<div class="flex-1">
									<input
										class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										type="number"
										bind:value={_user.duration}
										placeholder={$i18n.t('menuduration_placeholder')}
										autocomplete="off"
									/>
								</div>
							</div>
							<div class="flex flex-col w-full my-2">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuprice')}</div>

								<div class="flex-1">
									<input
										class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										type="number"
										bind:value={_user.price}
										placeholder={$i18n.t('menuprice_placeholder')}
										autocomplete="off"
										step="any"
									/>
								</div>
							</div>
							<div class="flex flex-col w-full my-2">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menucredits')}</div>

								<div class="flex-1 flex">
									<input
										class="w-full flex-1 text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
										type="number"
										bind:value={_user.credits}
										placeholder={$i18n.t('menucredits_placeholder')}
										autocomplete="off"
									/>

									<span class="flex-1 text-sm text-gray-500"
										>×{_user.duration ?? $i18n.t('menuduration')} = {_user.credits * _user.duration}
										{$i18n.t('Credit')}</span
									>
								</div>
							</div>

							<div class="flex justify-between w-full my-1">
								<div class=" mb-1 text-xs text-gray-500">{$i18n.t('menuis_active')}</div>

								<Switch bind:state={_user.is_active} />
							</div>
						{:else if tab === 'import'}
							<div>
								<div class="mb-3 w-full">
									<input
										id="upload-user-csv-input"
										hidden
										bind:files={inputFiles}
										type="file"
										accept=".csv"
									/>

									<button
										class="w-full text-sm font-medium py-3 bg-transparent hover:bg-gray-100 border border-dashed dark:border-gray-850 dark:hover:bg-gray-850 text-center rounded-xl"
										type="button"
										on:click={() => {
											document.getElementById('upload-user-csv-input')?.click();
										}}
									>
										{#if inputFiles}
											{inputFiles.length > 0 ? `${inputFiles.length}` : ''} document(s) selected.
										{:else}
											{$i18n.t('Click here to select a csv file.')}
										{/if}
									</button>
								</div>

								<div class=" text-xs text-gray-500">
									ⓘ {$i18n.t(
										'Ensure your CSV file includes 4 columns in this order: Name, Email, Password, Role.'
									)}
									<a
										class="underline dark:text-gray-200"
										href="{WEBUI_BASE_URL}/static/user-import.csv"
									>
										{$i18n.t('Click here to download user import template file.')}
									</a>
								</div>
							</div>
						{/if}
					</div>

					<div class="flex justify-end pt-3 text-sm font-medium">
						<button
							class="px-3.5 py-1.5 text-sm font-medium bg-black hover:bg-gray-900 text-white dark:bg-white dark:text-black dark:hover:bg-gray-100 transition rounded-full flex flex-row space-x-1 items-center {loading
								? ' cursor-not-allowed'
								: ''}"
							type="submit"
							disabled={loading}
						>
							{$i18n.t('Save')}

							{#if loading}
								<div class="ml-2 self-center">
									<svg
										class=" w-4 h-4"
										viewBox="0 0 24 24"
										fill="currentColor"
										xmlns="http://www.w3.org/2000/svg"
										><style>
											.spinner_ajPY {
												transform-origin: center;
												animation: spinner_AtaB 0.75s infinite linear;
											}
											@keyframes spinner_AtaB {
												100% {
													transform: rotate(360deg);
												}
											}
										</style><path
											d="M12,1A11,11,0,1,0,23,12,11,11,0,0,0,12,1Zm0,19a8,8,0,1,1,8-8A8,8,0,0,1,12,20Z"
											opacity=".25"
										/><path
											d="M10.14,1.16a11,11,0,0,0-9,8.92A1.59,1.59,0,0,0,2.46,12,1.52,1.52,0,0,0,4.11,10.7a8,8,0,0,1,6.66-6.61A1.42,1.42,0,0,0,12,2.69h0A1.57,1.57,0,0,0,10.14,1.16Z"
											class="spinner_ajPY"
										/></svg
									>
								</div>
							{/if}
						</button>
					</div>
				</form>
			</div>
		</div>
	</div>
</Modal>

<style>
	input::-webkit-outer-spin-button,
	input::-webkit-inner-spin-button {
		/* display: none; <- Crashes Chrome on hover */
		-webkit-appearance: none;
		margin: 0; /* <-- Apparently some margin are still there even though it's hidden */
	}

	.tabs::-webkit-scrollbar {
		display: none; /* for Chrome, Safari and Opera */
	}

	.tabs {
		-ms-overflow-style: none; /* IE and Edge */
		scrollbar-width: none; /* Firefox */
	}

	input[type='number'] {
		-moz-appearance: textfield; /* Firefox */
	}
</style>
